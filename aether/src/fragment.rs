//! TLS ClientHello fragmentation for the HTTP/2 MASQUE carrier.
//!
//! Two modes:
//!
//! - `tls_records` (default): the ClientHello TLS Record is split into several
//!   TLS Records, each with its own 5-byte header. The server reassembles them
//!   transparently (TLS allows handshake messages to span records), but a DPI
//!   that reads the SNI from a single record sees only a piece. This is what
//!   Xray calls "tlshello" fragmentation.
//!
//! - `!tls_records` (legacy): the ClientHello is written to the socket in
//!   several small chunks *without* re-framing. This is weaker, because a DPI
//!   that reassembles the TCP stream sees the original record. Kept for
//!   networks where the re-framed version is throttled.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::future::Future;
use std::time::Duration;

use bytes::Bytes;
use rand::RngExt;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// TLS content type for a handshake record.
const TLS_HANDSHAKE: u8 = 0x16;
/// Handshake message type for a ClientHello.
const TLS_CLIENT_HELLO: u8 = 0x01;
/// A TLS record header is 5 bytes: type, version (2), length (2).
const TLS_HEADER_LEN: usize = 5;

#[derive(Debug, Clone, Copy)]
pub struct FragmentConfig {
    pub enabled: bool,
    pub size_min: usize,
    pub size_max: usize,
    pub delay_min_ms: u64,
    pub delay_max_ms: u64,
    pub sni_split: bool,
    /// If true (default), wrap each fragment in its own TLS Record header
    /// (TLS Record Fragmentation). If false, split the raw TCP stream.
    pub tls_records: bool,
}

impl FragmentConfig {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            size_min: 1,
            size_max: 1,
            delay_min_ms: 0,
            delay_max_ms: 0,
            sni_split: false,
            tls_records: true,
        }
    }

    pub fn from_env() -> Self {
        // Real TLS Record Fragmentation is the default.
        let tls_records = std::env::var("AETHER_MASQUE_H2_FRAGMENT_TLS_RECORDS")
            .map(|v| is_truthy(&v))
            .unwrap_or(true);

        // ClientHello fragmentation is on by default: Iran's firewall resets a
        // whole ClientHello whose SNI ends in cloudflareclient.com, so the
        // handshake only completes when the SNI is split across records.
        let enabled = std::env::var("AETHER_MASQUE_H2_FRAGMENT")
            .map(|v| is_truthy(&v))
            .unwrap_or(true);

        // Different defaults per mode:
        //  - tls_records: bigger chunks means fewer records; 64..128 keeps a
        //    typical 400-byte ClientHello to 4-8 records.
        //  - tcp split: smaller chunks scatter the SNI over more segments.
        let default_sizes = if tls_records { (64, 128) } else { (8, 16) };
        let (size_min, size_max) = parse_range(
            &std::env::var("AETHER_MASQUE_H2_FRAGMENT_SIZE").unwrap_or_default(),
            default_sizes,
        );

        let (delay_min_ms, delay_max_ms) = parse_range(
            &std::env::var("AETHER_MASQUE_H2_FRAGMENT_DELAY").unwrap_or_default(),
            (2, 10),
        );

        let size_min = size_min.max(1) as usize;
        let size_max = (size_max.max(size_min as u64)) as usize;

        // Splitting at the SNI midpoint is on by default when TLS records are
        // used; without it the random chunk boundaries may miss the SNI.
        let sni_split = std::env::var("AETHER_MASQUE_H2_FRAGMENT_SNI")
            .map(|v| is_truthy(&v))
            .unwrap_or(tls_records);

        Self {
            enabled,
            size_min,
            size_max,
            delay_min_ms,
            delay_max_ms: delay_max_ms.max(delay_min_ms),
            sni_split,
            tls_records,
        }
    }

    fn pick_chunk_len(&self, remaining: usize) -> usize {
        let hi = self.size_max.max(1).min(remaining);
        let lo = self.size_min.max(1).min(hi);
        if lo >= hi {
            hi
        } else {
            rand::rng().random_range(lo..=hi)
        }
    }

    fn pick_delay(&self) -> Duration {
        if self.delay_max_ms == 0 {
            return Duration::ZERO;
        }
        let ms = if self.delay_max_ms <= self.delay_min_ms {
            self.delay_min_ms
        } else {
            rand::rng().random_range(self.delay_min_ms..=self.delay_max_ms)
        };
        Duration::from_millis(ms)
    }
}

pub(crate) fn is_truthy(v: &str) -> bool {
    matches!(
        v.trim().to_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn parse_range(spec: &str, default: (u64, u64)) -> (u64, u64) {
    let spec = spec.trim();
    if spec.is_empty() {
        return default;
    }
    match spec.split_once('-') {
        Some((a, b)) => {
            let lo = a.trim().parse().unwrap_or(default.0);
            let hi = b.trim().parse().unwrap_or(default.1);
            if hi < lo {
                (hi, lo)
            } else {
                (lo, hi)
            }
        }
        None => {
            let v = spec.parse().unwrap_or(default.0);
            (v, v)
        }
    }
}

/// The byte range of the SNI hostname inside a TLS ClientHello record, as
/// `(start, end)` offsets from the beginning of `buf`.
pub fn sni_host_range(buf: &[u8]) -> Option<(usize, usize)> {
    let take = |at: usize, n: usize| -> Option<usize> {
        let end = at.checked_add(n)?;
        let slice = buf.get(at..end)?;
        Some(slice.iter().fold(0usize, |acc, b| (acc << 8) | *b as usize))
    };

    if *buf.first()? != TLS_HANDSHAKE || *buf.get(5)? != TLS_CLIENT_HELLO {
        return None;
    }

    let mut at = 43usize;
    at += 1 + take(at, 1)?;
    at += 2 + take(at, 2)?;
    at += 1 + take(at, 1)?;

    let extensions_end = at + 2 + take(at, 2)?;
    at += 2;

    while at + 4 <= extensions_end {
        let kind = take(at, 2)?;
        let len = take(at + 2, 2)?;
        let body = at + 4;
        if kind == 0x0000 {
            let entry = body + 2;
            if take(entry, 1)? != 0 {
                return None;
            }
            let host_len = take(entry + 1, 2)?;
            let host = entry + 3;
            if host_len == 0 || host + host_len > buf.len() {
                return None;
            }
            return Some((host, host + host_len));
        }
        at = body + len;
    }

    None
}

/// Where to split the ClientHello body (the bytes after the TLS record header).
fn split_points(body_len: usize, record: &[u8], cfg: &FragmentConfig) -> Vec<usize> {
    let mut points: Vec<usize> = Vec::new();

    // 1. Split at the SNI midpoint, when configured and the SNI is present.
    if cfg.sni_split {
        if let Some((start, end)) = sni_host_range(record) {
            if start >= TLS_HEADER_LEN {
                let sni_start = start - TLS_HEADER_LEN;
                let sni_end = end.saturating_sub(TLS_HEADER_LEN);
                if sni_start < sni_end && sni_end <= body_len {
                    let mid = sni_start + (sni_end - sni_start) / 2;
                    if mid > 0 && mid < body_len {
                        points.push(mid);
                    }
                }
            }
        }
    }

    // 2. Size-based splits.
    let mut pos = 0;
    while pos < body_len {
        let chunk = cfg.pick_chunk_len(body_len - pos);
        let next = pos + chunk;
        if next < body_len {
            let too_close = points.iter().any(|&p| p.abs_diff(next) < cfg.size_min);
            if !too_close {
                points.push(next);
            }
        }
        pos = next;
    }

    points.sort_unstable();
    points.dedup();
    points
}

fn build_tls_record(content_type: u8, version: [u8; 2], body: &[u8]) -> Vec<u8> {
    let mut rec = Vec::with_capacity(TLS_HEADER_LEN + body.len());
    rec.push(content_type);
    rec.push(version[0]);
    rec.push(version[1]);
    rec.extend_from_slice(&(body.len() as u16).to_be_bytes());
    rec.extend_from_slice(body);
    rec
}

/// Split a TLS ClientHello record into several TLS Records.
///
/// Returns the new records in order. If the input is not a ClientHello
/// handshake record, or nothing useful to split is found, a single record
/// equal to the input is returned.
fn split_into_tls_records(record: &[u8], cfg: &FragmentConfig) -> Vec<Vec<u8>> {
    if record.len() < TLS_HEADER_LEN || record[0] != TLS_HANDSHAKE {
        return vec![record.to_vec()];
    }
    if record.len() > TLS_HEADER_LEN && record[TLS_HEADER_LEN] != TLS_CLIENT_HELLO {
        // Not a ClientHello (could be a server record, or something else).
        return vec![record.to_vec()];
    }

    let content_type = record[0];
    let version = [record[1], record[2]];
    let declared_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    let body_len = declared_len.min(record.len() - TLS_HEADER_LEN);
    let body = &record[TLS_HEADER_LEN..TLS_HEADER_LEN + body_len];

    // Anything under 2×size_min can't be split meaningfully.
    if body_len < cfg.size_min * 2 {
        return vec![record.to_vec()];
    }

    let points = split_points(body_len, record, cfg);
    if points.is_empty() {
        return vec![record.to_vec()];
    }

    let mut out = Vec::with_capacity(points.len() + 1);
    let mut prev = 0usize;
    for &point in &points {
        if point <= prev || point >= body_len {
            continue;
        }
        out.push(build_tls_record(content_type, version, &body[prev..point]));
        prev = point;
    }
    if prev < body_len {
        out.push(build_tls_record(content_type, version, &body[prev..]));
    }
    if out.is_empty() {
        out.push(record.to_vec());
    }
    out
}

fn split_tcp_stream(buf: &[u8], cfg: &FragmentConfig) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < buf.len() {
        let chunk = cfg.pick_chunk_len(buf.len() - pos);
        out.push(buf[pos..pos + chunk].to_vec());
        pos += chunk;
    }
    out
}

pub struct FragmentingStream<S> {
    inner: S,
    cfg: FragmentConfig,
    /// Fragments waiting to be written out.
    pending: VecDeque<Bytes>,
    /// Set once the ClientHello has been handled (or fragmentation is off).
    first_write_done: bool,
    /// Inter-fragment delay currently being observed.
    pending_delay: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<S: AsyncWrite + Unpin> FragmentingStream<S> {
    pub fn new(inner: S, cfg: FragmentConfig) -> Self {
        Self {
            inner,
            first_write_done: !cfg.enabled,
            cfg,
            pending: VecDeque::new(),
            pending_delay: None,
        }
    }

    /// Drain as much of `pending` as the inner stream will take, honouring the
    /// inter-fragment delay. `Poll::Pending` means the inner stream isn't ready
    /// or a delay is running; the caller will be woken when it's time.
    fn poll_drain_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(sleep) = self.pending_delay.as_mut() {
            match sleep.as_mut().poll(cx) {
                Poll::Ready(()) => self.pending_delay = None,
                Poll::Pending => return Poll::Pending,
            }
        }

        while let Some(chunk) = self.pending.pop_front() {
            match Pin::new(&mut self.inner).poll_write(cx, &chunk) {
                Poll::Ready(Ok(n)) if n == chunk.len() => {
                    if !self.pending.is_empty() {
                        let delay = self.cfg.pick_delay();
                        if !delay.is_zero() {
                            self.pending_delay = Some(Box::pin(tokio::time::sleep(delay)));
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                    }
                }
                Poll::Ready(Ok(n)) => {
                    // Partial write: keep the remainder and wait.
                    self.pending.push_front(chunk.slice(n..));
                    return Poll::Pending;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    self.pending.push_front(chunk);
                    return Poll::Pending;
                }
            }
        }

        Poll::Ready(Ok(()))
    }
}

impl<S> AsyncRead for FragmentingStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Once the server's answer starts arriving, the ClientHello is behind us.
        this.first_write_done = true;
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for FragmentingStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // If buffered fragments remain, drain them before accepting new data.
        if !this.pending.is_empty() || this.pending_delay.is_some() {
            match this.poll_drain_pending(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if !this.cfg.enabled || this.first_write_done {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }

        // First write of a TLS session: this is the ClientHello.
        if buf.len() >= TLS_HEADER_LEN && buf[0] == TLS_HANDSHAKE {
            this.first_write_done = true;

            let fragments = if this.cfg.tls_records {
                split_into_tls_records(buf, &this.cfg)
            } else {
                split_tcp_stream(buf, &this.cfg)
            };

            // Nothing to split: write as-is.
            if fragments.len() <= 1 {
                let only = fragments.into_iter().next().unwrap_or_else(|| buf.to_vec());
                return Pin::new(&mut this.inner).poll_write(cx, &only);
            }

            for frag in fragments {
                this.pending.push_back(Bytes::from(frag));
            }

            // Try to write as much as possible right now.
            match this.poll_drain_pending(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {}
            }

            // We accepted the whole of `buf`; the rest is buffered and will be
            // flushed on the next `poll_write` or `poll_flush` call.
            return Poll::Ready(Ok(buf.len()));
        }

        // Not a TLS record; shouldn't happen at the start of a TLS session.
        this.first_write_done = true;
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_drain_pending(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_drain_pending(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A TLS ClientHello record with a real SNI extension. The other extensions
    /// are padded so the record is long enough to split.
    fn client_hello(host: &str, pad: usize) -> Vec<u8> {
        let mut sni = vec![0x00];
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host.as_bytes());
        let mut list = (sni.len() as u16).to_be_bytes().to_vec();
        list.extend_from_slice(&sni);
        let mut sni_ext = vec![0x00, 0x00];
        sni_ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
        sni_ext.extend_from_slice(&list);

        // A pad extension of the given length (type 0x0021 is padding).
        let mut pad_ext = vec![0x00, 0x21];
        pad_ext.extend_from_slice(&(pad as u16).to_be_bytes());
        pad_ext.extend(std::iter::repeat(0u8).take(pad));

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&sni_ext);
        extensions.extend_from_slice(&pad_ext);

        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]);
        body.extend_from_slice(&[0x01, 0x00]);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut handshake = vec![0x01];
        let len = body.len();
        handshake.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        handshake.extend_from_slice(&body);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn body_of(record: &[u8]) -> &[u8] {
        let len = u16::from_be_bytes([record[3], record[4]]) as usize;
        &record[5..5 + len]
    }

    #[test]
    fn the_server_name_is_located_inside_a_client_hello() {
        let host = "api.cloudflareclient.com";
        let hello = client_hello(host, 0);
        let (start, end) = sni_host_range(&hello).expect("the name is in there");
        assert_eq!(&hello[start..end], host.as_bytes());
    }

    #[test]
    fn a_split_lands_in_the_middle_of_the_server_name() {
        let host = "api.cloudflareclient.com";
        let hello = client_hello(host, 0);
        let (start, end) = sni_host_range(&hello).expect("the name is in there");
        let split = start + (end - start) / 2;
        assert!(split > start && split < end);
    }

    #[test]
    fn anything_that_is_not_a_client_hello_is_left_alone() {
        assert!(sni_host_range(b"").is_none());
        assert!(sni_host_range(&[0x17, 0x03, 0x03, 0x00, 0x05, 0x01]).is_none());
        let truncated = &client_hello("example.com", 0)[..20];
        assert!(sni_host_range(truncated).is_none());
    }

    #[test]
    fn tls_record_fragmentation_produces_valid_records() {
        let host = "consumer-masque.cloudflareclient.com";
        let original = client_hello(host, 200);
        let cfg = FragmentConfig {
            enabled: true,
            size_min: 32,
            size_max: 64,
            delay_min_ms: 0,
            delay_max_ms: 0,
            sni_split: true,
            tls_records: true,
        };
        let fragments = split_into_tls_records(&original, &cfg);
        assert!(
            fragments.len() >= 2,
            "expected multiple records, got {}",
            fragments.len()
        );

        // Every fragment must be a well-formed TLS handshake record.
        for (i, frag) in fragments.iter().enumerate() {
            assert!(frag.len() >= TLS_HEADER_LEN, "fragment {i} too short");
            assert_eq!(frag[0], 0x16, "fragment {i}: wrong content type");
            assert_eq!(&frag[1..3], &[0x03, 0x01], "fragment {i}: wrong version");
            let len = u16::from_be_bytes([frag[3], frag[4]]) as usize;
            assert_eq!(
                frag.len(),
                TLS_HEADER_LEN + len,
                "fragment {i}: length header mismatch"
            );
        }

        // The bodies concatenated must equal the original body.
        let mut reassembled: Vec<u8> = Vec::new();
        for frag in &fragments {
            reassembled.extend_from_slice(body_of(frag));
        }
        assert_eq!(
            reassembled.as_slice(),
            body_of(&original),
            "the bodies must reassemble into the original ClientHello body"
        );
    }

    #[test]
    fn the_sni_midpoint_is_a_split_point() {
        let host = "consumer-masque.cloudflareclient.com";
        let original = client_hello(host, 100);
        let (start, _end) = sni_host_range(&original).unwrap();
        let mid_in_body = start + host.len() / 2 - TLS_HEADER_LEN;

        let cfg = FragmentConfig {
            enabled: true,
            size_min: 32,
            size_max: 64,
            delay_min_ms: 0,
            delay_max_ms: 0,
            sni_split: true,
            tls_records: true,
        };
        let fragments = split_into_tls_records(&original, &cfg);

        // Find the record boundary closest to the SNI midpoint.
        let mut cumulative = 0usize;
        let mut closest = usize::MAX;
        for frag in fragments.iter().take(fragments.len() - 1) {
            cumulative += body_of(frag).len();
            closest = closest.min(cumulative.abs_diff(mid_in_body));
        }
        assert!(
            closest <= 2,
            "the SNI midpoint {mid_in_body} is {closest} bytes from any boundary"
        );
    }

    #[test]
    fn a_short_hello_is_returned_unsplit() {
        let hello = client_hello("a.b", 0);
        let cfg = FragmentConfig {
            enabled: true,
            size_min: 200,
            size_max: 400,
            delay_min_ms: 0,
            delay_max_ms: 0,
            sni_split: true,
            tls_records: true,
        };
        let fragments = split_into_tls_records(&hello, &cfg);
        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0], hello);
    }

    #[test]
    fn a_non_handshake_record_passes_through() {
        let mut record = vec![0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5];
        let cfg = FragmentConfig {
            enabled: true,
            size_min: 1,
            size_max: 4,
            delay_min_ms: 0,
            delay_max_ms: 0,
            sni_split: true,
            tls_records: true,
        };
        let fragments = split_into_tls_records(&record, &cfg);
        assert_eq!(fragments.len(), 1);
        assert_eq!(fragments[0], record);

        // Also a non-ClientHello handshake record.
        record[0] = 0x16;
        record[5] = 0x02; // ServerHello
        let fragments = split_into_tls_records(&record, &cfg);
        assert_eq!(fragments.len(), 1);
    }

    #[test]
    fn the_shipped_defaults_are_sensible() {
        std::env::remove_var("AETHER_MASQUE_H2_FRAGMENT");
        std::env::remove_var("AETHER_MASQUE_H2_FRAGMENT_TLS_RECORDS");
        std::env::remove_var("AETHER_MASQUE_H2_FRAGMENT_SNI");
        std::env::remove_var("AETHER_MASQUE_H2_FRAGMENT_SIZE");
        std::env::remove_var("AETHER_MASQUE_H2_FRAGMENT_DELAY");

        let cfg = FragmentConfig::from_env();
        assert!(cfg.enabled, "fragmentation should be on by default");
        assert!(cfg.tls_records, "TLS record mode should be on by default");
        assert!(cfg.sni_split, "SNI splitting should be on by default");
        assert!(cfg.size_min >= 32 && cfg.size_max <= 256);
    }

    #[test]
    fn a_single_chunk_stream_can_be_written_through() {
        // A pure pass-through test: when fragmentation is off, bytes go
        // through unchanged.
        use tokio::io::AsyncWriteExt;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (mut a, b) = tokio::io::duplex(1024);
            let mut wrapped = FragmentingStream::new(b, FragmentConfig::disabled());
            let payload = b"hello world";
            let n = wrapped.write(payload).await.unwrap();
            assert_eq!(n, payload.len());
            let mut got = vec![0u8; payload.len()];
            tokio::io::AsyncReadExt::read_exact(&mut a, &mut got)
                .await
                .unwrap();
            assert_eq!(&got, payload);
        });
    }
}