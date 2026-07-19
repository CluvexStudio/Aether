use std::collections::HashMap;
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Checksum, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address, Ipv6Address};
use tokio::sync::{mpsc, oneshot};

use crate::error::{AetherError, Result};

/// Scale TCP/UDP buffers to available system memory.
/// Desktop (16GB+): 512KB TCP, 128KB UDP.  Router (128-512MB): proportionally smaller.
fn scaled_tcp_buf() -> usize {
    #[cfg(unix)]
    {
        let pages = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) };
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if pages > 0 && page_size > 0 {
            let total_mb = (pages as u64 * page_size as u64) / (1024 * 1024);
            return match total_mb {
                0..=256 => 64 * 1024,      // 128-256 MB: 64KB
                257..=1024 => 128 * 1024,   // 256MB-1GB: 128KB
                1025..=4096 => 256 * 1024,  // 1-4 GB: 256KB
                _ => 512 * 1024,            // 4GB+: 512KB (original)
            };
        }
    }
    512 * 1024 // fallback for non-unix or sysconf failure
}

fn scaled_udp_buf() -> usize {
    scaled_tcp_buf() / 4
}

const UDP_META: usize = 128;
const APP_QUEUE: usize = 4096;
const MAX_INGEST_PER_TICK: usize = 512;
const MAX_RECV_CHUNKS: usize = 128;

type OpenTcpResp = oneshot::Sender<std::result::Result<TcpConn, String>>;
type OpenUdpResp = oneshot::Sender<std::result::Result<UdpConn, String>>;

pub struct StackDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl StackDevice {
    fn new(mtu: usize) -> Self {
        Self {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu,
        }
    }
}

pub struct StackRxToken(Vec<u8>);
pub struct StackTxToken<'a>(&'a mut VecDeque<Vec<u8>>);

impl RxToken for StackRxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}

impl<'a> TxToken for StackTxToken<'a> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.push_back(buf);
        r
    }
}

impl Device for StackDevice {
    type RxToken<'a> = StackRxToken;
    type TxToken<'a> = StackTxToken<'a>;

    fn receive(&mut self, _t: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx.pop_front()?;
        Some((StackRxToken(pkt), StackTxToken(&mut self.tx)))
    }

    fn transmit(&mut self, _t: Instant) -> Option<Self::TxToken<'_>> {
        Some(StackTxToken(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps.checksum.ipv4 = Checksum::Tx;
        caps.checksum.tcp = Checksum::Tx;
        caps.checksum.udp = Checksum::Tx;
        caps
    }
}

pub enum Cmd {
    OpenTcp { dst: SocketAddr, resp: OpenTcpResp },
    OpenUdp { resp: OpenUdpResp },
    SetAddrs {
        v4: Option<(Ipv4Addr, u8)>,
        v6: Option<(Ipv6Addr, u8)>,
    },
}

pub enum DataIn {
    Tcp(usize, Vec<u8>),
    TcpClose(usize),
    Udp(usize, SocketAddr, Vec<u8>),
    UdpClose(usize),
}

pub struct TcpConn {
    pub id: usize,
    pub from_stack: mpsc::Receiver<Vec<u8>>,
    data_in: mpsc::Sender<DataIn>,
}

impl TcpConn {
    pub async fn send(&self, data: Vec<u8>) -> Result<()> {
        self.data_in
            .send(DataIn::Tcp(self.id, data))
            .await
            .map_err(|_| AetherError::Other("netstack closed".into()))
    }

    pub async fn close(&self) {
        let _ = self.data_in.send(DataIn::TcpClose(self.id)).await;
    }

    pub fn into_split(self) -> (TcpSender, mpsc::Receiver<Vec<u8>>) {
        (
            TcpSender {
                id: self.id,
                data_in: self.data_in,
            },
            self.from_stack,
        )
    }
}

pub struct TcpSender {
    id: usize,
    data_in: mpsc::Sender<DataIn>,
}

impl TcpSender {
    pub async fn send(&self, data: Vec<u8>) -> Result<()> {
        self.data_in
            .send(DataIn::Tcp(self.id, data))
            .await
            .map_err(|_| AetherError::Other("netstack closed".into()))
    }

    pub async fn close(&self) {
        let _ = self.data_in.send(DataIn::TcpClose(self.id)).await;
    }
}

pub struct UdpConn {
    pub id: usize,
    pub from_stack: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    data_in: mpsc::Sender<DataIn>,
}

impl UdpConn {
    pub async fn send_to(&self, dst: SocketAddr, data: Vec<u8>) -> Result<()> {
        self.data_in
            .send(DataIn::Udp(self.id, dst, data))
            .await
            .map_err(|_| AetherError::Other("netstack closed".into()))
    }

    pub async fn close(&self) {
        let _ = self.data_in.send(DataIn::UdpClose(self.id)).await;
    }

    pub fn into_split(self) -> (UdpSender, mpsc::Receiver<(SocketAddr, Vec<u8>)>) {
        (
            UdpSender {
                id: self.id,
                data_in: self.data_in,
            },
            self.from_stack,
        )
    }
}

pub struct UdpSender {
    id: usize,
    data_in: mpsc::Sender<DataIn>,
}

impl UdpSender {
    pub async fn send_to(&self, dst: SocketAddr, data: Vec<u8>) -> Result<()> {
        self.data_in
            .send(DataIn::Udp(self.id, dst, data))
            .await
            .map_err(|_| AetherError::Other("netstack closed".into()))
    }

    pub async fn close(&self) {
        let _ = self.data_in.send(DataIn::UdpClose(self.id)).await;
    }
}

#[derive(Clone)]
pub struct StackHandle {
    cmd_tx: mpsc::Sender<Cmd>,
}

impl StackHandle {
    pub async fn open_tcp(&self, dst: SocketAddr) -> Result<TcpConn> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.cmd_tx
            .send(Cmd::OpenTcp { dst, resp: resp_tx })
            .await
            .map_err(|_| AetherError::Other("netstack closed".into()))?;
        resp_rx
            .await
            .map_err(|_| AetherError::Other("netstack dropped".into()))?
            .map_err(AetherError::Other)
    }

    pub async fn open_udp(&self) -> Result<UdpConn> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.cmd_tx
            .send(Cmd::OpenUdp { resp: resp_tx })
            .await
            .map_err(|_| AetherError::Other("netstack closed".into()))?;
        resp_rx
            .await
            .map_err(|_| AetherError::Other("netstack dropped".into()))?
            .map_err(AetherError::Other)
    }

    pub async fn set_addrs(
        &self,
        v4: Option<(Ipv4Addr, u8)>,
        v6: Option<(Ipv6Addr, u8)>,
    ) -> Result<()> {
        self.cmd_tx
            .send(Cmd::SetAddrs { v4, v6 })
            .await
            .map_err(|_| AetherError::Other("netstack closed".into()))
    }
}

struct TcpState {
    handle: SocketHandle,
    to_app: mpsc::Sender<Vec<u8>>,
    from_stack_rx: Option<mpsc::Receiver<Vec<u8>>>,
    connect_resp: Option<OpenTcpResp>,
    pending: Vec<u8>,
    established: bool,
    half_closed: bool,
}

struct UdpState {
    handle: SocketHandle,
    to_app: mpsc::Sender<(SocketAddr, Vec<u8>)>,
}

pub struct NetStack {
    iface: Interface,
    device: StackDevice,
    sockets: SocketSet<'static>,
    tcp_conns: HashMap<usize, TcpState>,
    udp_conns: HashMap<usize, UdpState>,
    next_id: usize,
    next_port: u16,
    data_in_tx: mpsc::Sender<DataIn>,
}

fn strip_cidr(s: &str) -> &str {
    match s.split_once('/') {
        Some((ip, _)) => ip,
        None => s,
    }
}

fn to_ip_address(ip: IpAddr) -> IpAddress {
    match ip {
        IpAddr::V4(v4) => IpAddress::Ipv4(Ipv4Address::from(v4)),
        IpAddr::V6(v6) => IpAddress::Ipv6(Ipv6Address::from(v6)),
    }
}

fn to_ip_endpoint(addr: SocketAddr) -> IpEndpoint {
    IpEndpoint::new(to_ip_address(addr.ip()), addr.port())
}

fn cidr_prefix(s: &str) -> Option<u8> {
    s.split_once('/').and_then(|(_, p)| p.parse().ok())
}

fn parse_v4(s: &str) -> Result<Option<(Ipv4Addr, u8)>> {
    if s.is_empty() {
        return Ok(None);
    }
    let ip: Ipv4Addr = strip_cidr(s)
        .parse()
        .map_err(|_| AetherError::Other(format!("bad ipv4 {s}")))?;
    Ok(Some((ip, cidr_prefix(s).unwrap_or(32))))
}

fn parse_v6(s: &str) -> Result<Option<(Ipv6Addr, u8)>> {
    if s.is_empty() {
        return Ok(None);
    }
    let ip: Ipv6Addr = strip_cidr(s)
        .parse()
        .map_err(|_| AetherError::Other(format!("bad ipv6 {s}")))?;
    Ok(Some((ip, cidr_prefix(s).unwrap_or(128))))
}

fn routable_prefix_v4(p: u8) -> u8 {
    if p >= 31 {
        24
    } else {
        p
    }
}

fn routable_prefix_v6(p: u8) -> u8 {
    if p >= 127 {
        64
    } else {
        p
    }
}

fn apply_addrs(
    iface: &mut Interface,
    v4: Option<(Ipv4Addr, u8)>,
    v6: Option<(Ipv6Addr, u8)>,
) {
    iface.update_ip_addrs(|addrs| {
        addrs.clear();
        if let Some((ip, p)) = v4 {
            let _ = addrs.push(IpCidr::new(
                IpAddress::Ipv4(Ipv4Address::from(ip)),
                routable_prefix_v4(p),
            ));
        }
        if let Some((ip, p)) = v6 {
            let _ = addrs.push(IpCidr::new(
                IpAddress::Ipv6(Ipv6Address::from(ip)),
                routable_prefix_v6(p),
            ));
        }
    });

    if let Some((ip, _)) = v4 {
        let o = ip.octets();
        let host = if o[3] == 1 { 2 } else { 1 };
        let gw = Ipv4Address::new(o[0], o[1], o[2], host);
        let _ = iface.routes_mut().add_default_ipv4_route(gw);
    }
    if let Some((ip, _)) = v6 {
        let mut o = ip.octets();
        o[15] = if o[15] == 1 { 2 } else { 1 };
        let _ = iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::from(o));
    }
}

fn endpoint_to_socketaddr(ep: IpEndpoint) -> SocketAddr {
    let ip = match ep.addr {
        IpAddress::Ipv4(v4) => IpAddr::V4(v4.into()),
        IpAddress::Ipv6(v6) => IpAddr::V6(v6.into()),
    };
    SocketAddr::new(ip, ep.port)
}

pub fn spawn(
    ipv4: &str,
    ipv6: &str,
    mtu: usize,
    inbound_rx: mpsc::Receiver<Vec<u8>>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
) -> Result<StackHandle> {
    let mut device = StackDevice::new(mtu);

    let config = Config::new(HardwareAddress::Ip);
    let mut iface = Interface::new(config, &mut device, Instant::now());

    let v4 = parse_v4(ipv4)?;
    let v6 = parse_v6(ipv6)?;
    apply_addrs(&mut iface, v4, v6);

    let (cmd_tx, cmd_rx) = mpsc::channel(256);
    let (data_in_tx, data_in_rx) = mpsc::channel(APP_QUEUE);

    let stack = NetStack {
        iface,
        device,
        sockets: SocketSet::new(Vec::new()),
        tcp_conns: HashMap::new(),
        udp_conns: HashMap::new(),
        next_id: 1,
        next_port: 49152,
        data_in_tx: data_in_tx.clone(),
    };

    tokio::spawn(run(stack, cmd_rx, data_in_rx, inbound_rx, outbound_tx));

    Ok(StackHandle { cmd_tx })
}

fn alloc_port(p: &mut u16) -> u16 {
    let port = *p;
    *p = if port >= 65000 { 49152 } else { port + 1 };
    port
}

async fn run(
    mut s: NetStack,
    mut cmd_rx: mpsc::Receiver<Cmd>,
    mut data_in_rx: mpsc::Receiver<DataIn>,
    mut inbound_rx: mpsc::Receiver<Vec<u8>>,
    outbound_tx: mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    loop {
        let now = Instant::now();
        let poll_outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            s.iface.poll(now, &mut s.device, &mut s.sockets);
        }));
        if poll_outcome.is_err() {
            s.device.rx.clear();
            s.device.tx.clear();
        }
        service_tcp(&mut s).await;
        service_udp(&mut s).await;
        flush_tx(&mut s, &outbound_tx).await;

        let delay = s
            .iface
            .poll_delay(Instant::now(), &s.sockets)
            .map(|d| std::time::Duration::from_micros(d.total_micros()));

        tokio::select! {
            biased;

            maybe = inbound_rx.recv() => {
                match maybe {
                    Some(pkt) => {
                        s.device.rx.push_back(pkt);
                        let mut n = 0;
                        while n < MAX_INGEST_PER_TICK {
                            match inbound_rx.try_recv() {
                                Ok(p) => { s.device.rx.push_back(p); n += 1; }
                                Err(_) => break,
                            }
                        }
                    }
                    None => return Ok(()),
                }
            }

            maybe = cmd_rx.recv() => {
                match maybe {
                    Some(cmd) => handle_cmd(&mut s, cmd),
                    None => return Ok(()),
                }
            }

            maybe = data_in_rx.recv() => {
                if let Some(d) = maybe {
                    handle_data(&mut s, d);
                    while let Ok(d2) = data_in_rx.try_recv() {
                        handle_data(&mut s, d2);
                    }
                }
            }

            _ = sleep_opt(delay) => {}
        }
    }
}

async fn sleep_opt(delay: Option<std::time::Duration>) {
    match delay {
        Some(d) => tokio::time::sleep(d).await,
        None => std::future::pending::<()>().await,
    }
}

fn handle_cmd(s: &mut NetStack, cmd: Cmd) {
    match cmd {
        Cmd::OpenTcp { dst, resp } => {
            let rx_buf = tcp::SocketBuffer::new(vec![0u8; scaled_tcp_buf()]);
            let tx_buf = tcp::SocketBuffer::new(vec![0u8; scaled_tcp_buf()]);
            let mut socket = tcp::Socket::new(rx_buf, tx_buf);
            socket.set_nagle_enabled(false);

            let local_port = alloc_port(&mut s.next_port);
            let remote = to_ip_endpoint(dst);

            if let Err(e) = socket.connect(s.iface.context(), remote, local_port) {
                let _ = resp.send(Err(format!("connect: {e:?}")));
                return;
            }

            let handle = s.sockets.add(socket);
            let id = s.next_id;
            s.next_id += 1;

            let (to_app_tx, to_app_rx) = mpsc::channel(APP_QUEUE);

            s.tcp_conns.insert(
                id,
                TcpState {
                    handle,
                    to_app: to_app_tx,
                    from_stack_rx: Some(to_app_rx),
                    connect_resp: Some(resp),
                    pending: Vec::new(),
                    established: false,
                    half_closed: false,
                },
            );
        }
        Cmd::OpenUdp { resp } => {
            let rx_meta = vec![udp::PacketMetadata::EMPTY; UDP_META];
            let tx_meta = vec![udp::PacketMetadata::EMPTY; UDP_META];
            let rx_buf = udp::PacketBuffer::new(rx_meta, vec![0u8; scaled_udp_buf()]);
            let tx_buf = udp::PacketBuffer::new(tx_meta, vec![0u8; scaled_udp_buf()]);
            let mut socket = udp::Socket::new(rx_buf, tx_buf);

            let local_port = alloc_port(&mut s.next_port);
            if let Err(e) = socket.bind(local_port) {
                let _ = resp.send(Err(format!("bind: {e:?}")));
                return;
            }

            let handle = s.sockets.add(socket);
            let id = s.next_id;
            s.next_id += 1;

            let (to_app_tx, to_app_rx) = mpsc::channel(APP_QUEUE);
            s.udp_conns.insert(id, UdpState { handle, to_app: to_app_tx });

            let conn = UdpConn {
                id,
                from_stack: to_app_rx,
                data_in: s.data_in_tx.clone(),
            };
            let _ = resp.send(Ok(conn));
        }
        Cmd::SetAddrs { v4, v6 } => {
            apply_addrs(&mut s.iface, v4, v6);
            log::info!("netstack addresses synchronized from edge capsule");
        }
    }
}

fn handle_data(s: &mut NetStack, d: DataIn) {
    match d {
        DataIn::Tcp(id, data) => {
            if let Some(st) = s.tcp_conns.get_mut(&id) {
                st.pending.extend_from_slice(&data);
            }
        }
        DataIn::TcpClose(id) => {
            if let Some(st) = s.tcp_conns.get_mut(&id) {
                st.half_closed = true;
            }
        }
        DataIn::Udp(id, dst, data) => {
            if let Some(st) = s.udp_conns.get(&id) {
                let sock = s.sockets.get_mut::<udp::Socket>(st.handle);
                let _ = sock.send_slice(&data, to_ip_endpoint(dst));
            }
        }
        DataIn::UdpClose(id) => {
            if let Some(st) = s.udp_conns.remove(&id) {
                s.sockets.remove(st.handle);
            }
        }
    }
}

async fn service_tcp(s: &mut NetStack) {
    let ids: Vec<usize> = s.tcp_conns.keys().copied().collect();

    for id in ids {
        let handle = match s.tcp_conns.get(&id) {
            Some(st) => st.handle,
            None => continue,
        };

        let state = s.sockets.get_mut::<tcp::Socket>(handle).state();
        let data_in_tx = s.data_in_tx.clone();

        if !s.tcp_conns[&id].established && state == tcp::State::Established {
            if let Some(st) = s.tcp_conns.get_mut(&id) {
                st.established = true;
                if let (Some(resp), Some(rx)) = (st.connect_resp.take(), st.from_stack_rx.take()) {
                    let conn = TcpConn {
                        id,
                        from_stack: rx,
                        data_in: data_in_tx.clone(),
                    };
                    let _ = resp.send(Ok(conn));
                }
            }
        }

        if !s.tcp_conns[&id].established
            && matches!(state, tcp::State::Closed | tcp::State::TimeWait)
        {
            if let Some(st) = s.tcp_conns.get_mut(&id) {
                if let Some(resp) = st.connect_resp.take() {
                    let _ = resp.send(Err("connection refused".into()));
                }
            }
            s.sockets.remove(handle);
            s.tcp_conns.remove(&id);
            continue;
        }

        {
            let socket = s.sockets.get_mut::<tcp::Socket>(handle);
            if socket.can_send() {
                let st = s.tcp_conns.get_mut(&id).unwrap();
                if !st.pending.is_empty() {
                    let sent = socket.send_slice(&st.pending).unwrap_or(0);
                    if sent > 0 {
                        st.pending.drain(0..sent);
                    }
                }
            }
        }

        {
            let pending_empty = s.tcp_conns[&id].pending.is_empty();
            let half = s.tcp_conns[&id].half_closed;
            if half && pending_empty {
                s.sockets.get_mut::<tcp::Socket>(handle).close();
            }
        }

        let mut chunks: Vec<Vec<u8>> = Vec::new();
        {
            let socket = s.sockets.get_mut::<tcp::Socket>(handle);
            while socket.can_recv() && chunks.len() < MAX_RECV_CHUNKS {
                match socket.recv(|buf| {
                    let v = buf.to_vec();
                    (v.len(), v)
                }) {
                    Ok(v) if !v.is_empty() => chunks.push(v),
                    _ => break,
                }
            }
        }

        let to_app = s.tcp_conns[&id].to_app.clone();
        let mut app_gone = false;
        for v in chunks {
            if to_app.send(v).await.is_err() {
                app_gone = true;
                break;
            }
        }
        if app_gone {
            s.sockets.get_mut::<tcp::Socket>(handle).close();
        }

        let st_state = s.sockets.get_mut::<tcp::Socket>(handle).state();
        if matches!(st_state, tcp::State::CloseWait) {
            s.sockets.get_mut::<tcp::Socket>(handle).close();
        }
        if matches!(st_state, tcp::State::Closed) && s.tcp_conns[&id].established {
            s.sockets.remove(handle);
            s.tcp_conns.remove(&id);
        }
    }
}

async fn service_udp(s: &mut NetStack) {
    let ids: Vec<usize> = s.udp_conns.keys().copied().collect();

    for id in ids {
        let handle = match s.udp_conns.get(&id) {
            Some(st) => st.handle,
            None => continue,
        };

        let mut packets: Vec<(SocketAddr, Vec<u8>)> = Vec::new();
        {
            let socket = s.sockets.get_mut::<udp::Socket>(handle);
            while socket.can_recv() && packets.len() < MAX_RECV_CHUNKS {
                match socket.recv() {
                    Ok((data, meta)) => {
                        packets.push((endpoint_to_socketaddr(meta.endpoint), data.to_vec()));
                    }
                    Err(_) => break,
                }
            }
        }

        let to_app = s.udp_conns[&id].to_app.clone();
        for p in packets {
            if to_app.send(p).await.is_err() {
                break;
            }
        }
    }
}

async fn flush_tx(s: &mut NetStack, outbound_tx: &mpsc::Sender<Vec<u8>>) {
    while let Some(pkt) = s.device.tx.pop_front() {
        if outbound_tx.send(pkt).await.is_err() {
            return;
        }
    }
}
