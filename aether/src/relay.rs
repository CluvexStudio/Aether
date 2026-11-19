use std::net::SocketAddr;

use crate::error::{AetherError, Result};

#[derive(Debug, thiserror::Error)]
pub enum TaskError {
    #[error("{0} stopped")]
    Stopped(String),
    #[error("{0} was cancelled")]
    Cancelled(String),
    #[error("{what} panicked: {reason}")]
    Panicked { what: String, reason: String },
}
use crate::{netstack, socks};

pub(crate) async fn spawn_tcp_forwarder(
    outer: &netstack::StackHandle,
    remote: SocketAddr,
) -> Result<(SocketAddr, TaskGuard)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let local = listener.local_addr()?;
    let stack = outer.clone();

    let task = tokio::spawn(async move {
        let mut clients = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((sock, _)) = accepted else { break };
                    let stack = stack.clone();
                    clients.spawn(async move {
                        match stack.open_tcp(remote).await {
                            Ok(conn) => {
                                let (sender, from_stack) = conn.into_split();
                                socks::relay_tunneled(
                                    sock,
                                    sender,
                                    from_stack,
                                    socks::half_close_linger(),
                                )
                                .await;
                            }
                            Err(e) => log::warn!(
                                "[-] the inner hop could not reach {remote} through the outer tunnel: {e}"
                            ),
                        }
                    });
                }
                Some(_) = clients.join_next(), if !clients.is_empty() => {}
            }
        }
    });

    Ok((local, TaskGuard(vec![task.abort_handle()])))
}

pub(crate) struct TaskGuard(pub(crate) Vec<tokio::task::AbortHandle>);

impl TaskGuard {
    pub(crate) fn new() -> Self {
        Self(Vec::new())
    }

    pub(crate) fn push(&mut self, handle: tokio::task::AbortHandle) {
        self.0.push(handle);
    }
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        for handle in self.0.drain(..) {
            handle.abort();
        }
    }
}

pub(crate) async fn spawn_udp_forwarder(
    outer: &netstack::StackHandle,
    remote: SocketAddr,
) -> Result<(SocketAddr, TaskGuard)> {
    let sock = std::sync::Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await?);
    let local = sock.local_addr()?;

    let udp = outer.open_udp().await?;
    let (udp_tx, mut udp_rx) = udp.into_split();

    let inner_peer: std::sync::Arc<tokio::sync::Mutex<Option<SocketAddr>>> =
        std::sync::Arc::new(tokio::sync::Mutex::new(None));

    let up_sock = sock.clone();
    let up_peer = inner_peer.clone();
    let up_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, from)) = up_sock.recv_from(&mut buf).await {
            {
                let mut known = up_peer.lock().await;
                if *known != Some(from) {
                    if let Some(previous) = *known {
                        log::debug!("inner udp forwarder follows {from} now, was {previous}");
                    }
                    *known = Some(from);
                }
            }
            if udp_tx.send_to(remote, buf[..n].to_vec()).await.is_err() {
                break;
            }
        }
    });

    let down_sock = sock.clone();
    let down_peer = inner_peer.clone();
    let down_task = tokio::spawn(async move {
        while let Some((_src, data)) = udp_rx.recv().await {
            let dst = *down_peer.lock().await;
            if let Some(dst) = dst {
                let _ = down_sock.send_to(&data, dst).await;
            }
        }
    });

    let guard = TaskGuard(vec![up_task.abort_handle(), down_task.abort_handle()]);

    Ok((local, guard))
}

pub(crate) fn join_outcome(
    what: &str,
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
) -> Result<()> {
    match result {
        Ok(Ok(())) => Err(AetherError::from(TaskError::Stopped(what.to_string()))),
        Ok(Err(e)) => Err(e),
        Err(e) if e.is_cancelled() => {
            Err(AetherError::from(TaskError::Cancelled(what.to_string())))
        }
        Err(e) => Err(AetherError::from(TaskError::Panicked {
            what: what.to_string(),
            reason: e.to_string(),
        })),
    }
}
