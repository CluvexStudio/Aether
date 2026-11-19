use std::net::SocketAddr;

use crate::error::{AetherError, Result};
use crate::relay::TaskGuard;
use crate::upstream;

pub(crate) fn watch_chain(
    name: &'static str,
    chain: tokio::task::JoinHandle<Result<()>>,
    core_end: tokio::sync::mpsc::UnboundedSender<AetherError>,
    guard: &mut TaskGuard,
) {
    let chain_task = chain.abort_handle();
    let watch = tokio::spawn(async move {
        let e = match chain.await {
            Ok(Err(e)) => e,
            Ok(Ok(())) => AetherError::Other(format!("{name} inside the tunnel stopped")),
            Err(failed) if failed.is_cancelled() => return,
            Err(failed) => AetherError::Other(format!("{name} inside the tunnel failed: {failed}")),
        };
        log::error!(target: "aether", "[-] {name}: {e}");
        let _ = core_end.send(e);
    });
    guard.push(watch.abort_handle());
    guard.push(chain_task);
}

pub(crate) async fn until_core_end(
    session: impl std::future::Future<Output = Result<()>>,
    mut core_ended: tokio::sync::mpsc::UnboundedReceiver<AetherError>,
) -> Result<()> {
    tokio::select! {
        result = session => result,
        Some(e) = core_ended.recv() => Err(e),
    }
}

pub(crate) fn carrier_upstream(name: &str, socks: SocketAddr) -> Result<String> {
    let setting = format!("socks5://{socks}");
    upstream::Upstream::parse(&setting).map_err(|e| {
        AetherError::Other(format!(
            "{name} listens on {socks}, which the tunnel cannot be dialled through ({}); \
             aether ends rather than dial around {name}",
            e.detail()
        ))
    })?;
    Ok(setting)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tunnel_is_dialled_through_a_carrier_it_can_be_dialled_through() {
        let tor: SocketAddr = "127.0.0.1:9050".parse().unwrap();
        assert_eq!(
            carrier_upstream("tor", tor).unwrap(),
            "socks5://127.0.0.1:9050"
        );
        let psiphon: SocketAddr = "[::1]:1080".parse().unwrap();
        assert_eq!(
            carrier_upstream("psiphon", psiphon).unwrap(),
            "socks5://[::1]:1080"
        );
    }

    #[test]
    fn a_carrier_the_tunnel_cannot_be_dialled_through_ends_aether() {
        let unbound: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let error = carrier_upstream("tor", unbound).unwrap_err().to_string();
        assert!(
            error.contains("aether ends rather than dial around tor")
                && !error.contains("(other: "),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_session_ends_when_tor_or_psiphon_inside_the_tunnel_ends() {
        let (end, ended) = tokio::sync::mpsc::unbounded_channel::<AetherError>();
        drop(end);
        assert!(until_core_end(async { Ok(()) }, ended).await.is_ok());
        let (_end, ended) = tokio::sync::mpsc::unbounded_channel::<AetherError>();
        let failed = until_core_end(async { Err(AetherError::Cancelled) }, ended).await;
        assert!(matches!(failed, Err(AetherError::Cancelled)));

        let (end, ended) = tokio::sync::mpsc::unbounded_channel::<AetherError>();
        let report = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            let _ = end.send(AetherError::Other(
                "psiphon stopped before it was ready".into(),
            ));
        });
        let session = std::future::pending::<Result<()>>();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            until_core_end(session, ended),
        )
        .await
        .expect("the end of Tor or Psiphon inside ends the session");
        match result {
            Err(AetherError::Other(why)) => assert_eq!(why, "psiphon stopped before it was ready"),
            other => panic!("expected the chain's error, got {other:?}"),
        }
        report.await.unwrap();
    }

    static LOGGED_ERRORS: std::sync::Mutex<Vec<(String, String)>> =
        std::sync::Mutex::new(Vec::new());

    struct ErrorCapture;

    impl log::Log for ErrorCapture {
        fn enabled(&self, metadata: &log::Metadata) -> bool {
            metadata.level() == log::Level::Error
        }

        fn log(&self, record: &log::Record) {
            if self.enabled(record.metadata()) {
                LOGGED_ERRORS
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push((record.target().to_string(), record.args().to_string()));
            }
        }

        fn flush(&self) {}
    }

    fn capture_errors() {
        static CAPTURE: ErrorCapture = ErrorCapture;
        static INSTALL: std::sync::Once = std::sync::Once::new();
        INSTALL.call_once(|| {
            log::set_logger(&CAPTURE).expect("no other logger is set in the tests");
            log::set_max_level(log::LevelFilter::Error);
        });
    }

    fn logged_errors() -> Vec<(String, String)> {
        LOGGED_ERRORS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    #[tokio::test]
    async fn the_end_of_tor_or_psiphon_inside_is_reported_however_it_ends() {
        capture_errors();
        let next = |name: &'static str, chain: tokio::task::JoinHandle<Result<()>>| async move {
            let (end, mut ended) = tokio::sync::mpsc::unbounded_channel::<AetherError>();
            let mut chains = TaskGuard::new();
            watch_chain(name, chain, end, &mut chains);
            let reported = tokio::time::timeout(std::time::Duration::from_secs(2), ended.recv())
                .await
                .expect("the end is reported")
                .expect("with its reason");
            drop(chains);
            reported
        };

        let failed = tokio::spawn(async {
            Err(AetherError::Other(
                "the tor socks5 listener cannot use 127.0.0.1:1".into(),
            ))
        });
        let reported = next("tor", failed).await;
        assert!(
            matches!(&reported, AetherError::Other(why) if why.starts_with("the tor socks5 listener")),
            "{reported:?}"
        );
        let line = format!("[-] tor: {reported}");
        assert!(
            logged_errors()
                .iter()
                .any(|(target, message)| target == "aether" && *message == line),
            "{line} is not among {:?}",
            logged_errors()
        );

        let returned = tokio::spawn(async { Ok(()) });
        let reported = next("psiphon", returned).await;
        assert!(
            matches!(&reported, AetherError::Other(why) if why == "psiphon inside the tunnel stopped"),
            "{reported:?}"
        );

        let panicked = tokio::spawn(async {
            if std::hint::black_box(true) {
                panic!("a bug in the chain");
            }
            Ok(())
        });
        let reported = next("tor", panicked).await;
        assert!(
            matches!(&reported, AetherError::Other(why) if why.starts_with("tor inside the tunnel failed")),
            "{reported:?}"
        );
    }

    #[tokio::test]
    async fn a_chain_ends_with_the_core_and_is_not_reported_as_ended_by_itself() {
        capture_errors();
        let (alive, gone) = tokio::sync::oneshot::channel::<()>();
        let chain = tokio::spawn(async move {
            let _alive = alive;
            std::future::pending::<Result<()>>().await
        });
        let (end, mut ended) = tokio::sync::mpsc::unbounded_channel::<AetherError>();
        let mut chains = TaskGuard::new();
        watch_chain("ended-with-the-core", chain, end, &mut chains);

        drop(chains);
        tokio::time::timeout(std::time::Duration::from_secs(2), gone)
            .await
            .expect("the chain is ended, letting go of what it held")
            .expect_err("dropped, not finished");
        let report = tokio::time::timeout(std::time::Duration::from_secs(2), ended.recv())
            .await
            .expect("the watch is ended as well");
        assert!(report.is_none(), "{report:?}");
        assert!(
            !logged_errors()
                .iter()
                .any(|(_, message)| message.contains("ended-with-the-core")),
            "{:?}",
            logged_errors()
        );
    }
}
