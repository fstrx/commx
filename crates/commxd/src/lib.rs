//! commxd as a library: the commx node.
//!
//! The desktop `commxd` binary and the Android app both run [`run`]; the only
//! difference is how the UI connects ([`Control`]): a private unix socket /
//! named pipe on desktop, an in-process pipe on Android.

mod call;
mod files;
mod ipc_server;
mod killswitch;
mod net;
mod power;
mod state;
mod supervise;
mod transport;
mod udp;
mod web;

pub use commx_core::local_ipc::{Reader, Writer};
pub use supervise::install_panic_hook;

use anyhow::{Context, Result};
use commx_core::local_ipc;
use std::future::Future;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Semaphore};

use state::{lock, Daemon, Shared};
use transport::{Net, NodeKey};

/// Connections allowed in the handshake/join phase at once.
const MAX_PREAUTH: usize = 32;

pub struct Config {
    /// Where encrypted alias files and blobs live.
    pub data_dir: PathBuf,
    /// Address to accept peers on.
    pub listen: String,
    /// Address put in invites, if peers reach us differently.
    pub advertise: Option<String>,
    /// Hold an OS sleep inhibitor while rooms are live (desktop only; on
    /// Android the app holds a wake lock instead).
    pub keep_awake: bool,
    pub tor: bool,
    pub tor_bin: String,
    pub no_udp: bool,
    /// Serve the browser client (files in this dir) and accept browser
    /// members over WebSocket on the peer port.
    pub web_dir: Option<PathBuf>,
    /// Serve the browser client over HTTPS (self-signed, per run). Browsers
    /// only allow the microphone in a secure context.
    pub web_tls: bool,
}

/// How UI clients reach the daemon.
pub enum Control {
    /// Unix socket path / Windows pipe name, restricted to the current user.
    Endpoint(String),
    /// In-process connections (Android): each item is one client's pipe.
    InProcess(mpsc::UnboundedReceiver<(Reader, Writer)>),
}

/// Create a directory only we can read. On Windows and Android the
/// user/app-private location's inherited permissions already restrict it.
pub fn private_dir(p: &Path) -> Result<()> {
    std::fs::create_dir_all(p)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Best guess at our LAN address. A UDP "connect" picks a route without
/// sending anything.
fn guess_ip() -> IpAddr {
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| s.connect("192.0.2.1:9").map(|_| s))
        .and_then(|s| s.local_addr())
        .map(|a| a.ip())
        .unwrap_or(IpAddr::from([127, 0, 0, 1]))
}

/// Run the node until `shutdown` resolves, then nuke every room (going down
/// is a node drop) and return.
pub async fn run(cfg: Config, control: Control, shutdown: impl Future<Output = ()>) -> Result<()> {
    let data_dir = cfg.data_dir.clone();
    private_dir(&data_dir)?;
    let control = match control {
        Control::Endpoint(endpoint) => {
            // Create a missing socket parent privately, but never chmod an existing
            // directory (it might be /tmp). The socket itself is 0600 and peer-UID checked.
            #[cfg(unix)]
            if let Some(parent) = Path::new(&endpoint).parent().filter(|p| !p.as_os_str().is_empty() && !p.exists()) {
                private_dir(parent)?;
            }
            let l = local_ipc::Listener::bind(&endpoint).with_context(|| format!("control endpoint {endpoint}"))?;
            ipc_server::ControlSource::Listener(Arc::new(tokio::sync::Mutex::new(l)))
        }
        Control::InProcess(rx) => ipc_server::ControlSource::InProcess(Arc::new(tokio::sync::Mutex::new(rx))),
    };
    files::purge_orphans(&data_dir);

    // In Tor mode only tor itself may reach us, so listen on loopback.
    let listen = if cfg.tor { "127.0.0.1:0".to_string() } else { cfg.listen.clone() };
    let tcp = TcpListener::bind(&listen).await.with_context(|| format!("listen on {listen}"))?;
    let bound: SocketAddr = tcp.local_addr()?;
    let key = NodeKey::generate()?;
    let transport = if cfg.tor {
        let net = Arc::new(Net::tor(key, bound.port()));
        let tor_dir = data_dir.join("tor");
        private_dir(&tor_dir)?;
        net.start_tor(cfg.tor_bin.clone(), tor_dir);
        net
    } else {
        let advertise = cfg.advertise.clone().unwrap_or_else(|| {
            let ip = if bound.ip().is_unspecified() { guess_ip() } else { bound.ip() };
            SocketAddr::new(ip, bound.port()).to_string()
        });
        Arc::new(Net::tcp(key, bound.port(), advertise))
    };

    let shared: Shared = Arc::new(Mutex::new(Daemon::new(data_dir, transport.clone(), cfg.keep_awake)));
    let web = match cfg.web_dir.clone() {
        Some(dir) => {
            let tls = if cfg.web_tls { Some(web::Tls::generate(&transport.advertised())?) } else { None };
            if let Some(t) = &tls {
                eprintln!("web client over https; certificate SHA-256 {}", t.fingerprint);
            }
            let mut d = lock(&shared);
            d.web = Some(state::WebInfo { https: tls.is_some(), cert: tls.as_ref().map(|t| t.fingerprint.clone()) });
            Some(web::WebServe { dir, tls })
        }
        None => None,
    };
    let web_dir = Arc::new(web);
    // Voice fast path, direct mode only: Tor mode must never open UDP.
    if !cfg.tor && !cfg.no_udp {
        match tokio::net::UdpSocket::bind(bound).await {
            Ok(sock) => lock(&shared).udp_out = Some(udp::start(shared.clone(), sock)),
            Err(e) => eprintln!("udp {bound} unavailable ({e}); voice will use tcp"),
        }
    }
    eprintln!("commxd up: {}", transport.label());

    // Core service loops run supervised: if one dies it's restarted, and the
    // daemon (with every room on it) keeps going. See supervise.rs.
    {
        let (shared, transport) = (shared.clone(), transport.clone());
        let tcp = Arc::new(tcp);
        let preauth = Arc::new(Semaphore::new(MAX_PREAUTH));
        supervise::supervise("peer listener", move || {
            let (shared, transport, tcp, preauth) = (shared.clone(), transport.clone(), tcp.clone(), preauth.clone());
            let web_dir = web_dir.clone();
            async move {
                loop {
                    let stream = match transport.accept(&tcp).await {
                        Ok(s) => s,
                        Err(_) => {
                            supervise::io_backoff().await;
                            continue;
                        }
                    };
                    // Shed load instead of queueing unauthenticated strangers.
                    let Ok(permit) = preauth.clone().try_acquire_owned() else { continue };
                    tokio::spawn(net::handle_inbound(shared.clone(), transport.clone(), stream, permit, web_dir.clone()));
                }
            }
        });
    }
    {
        let (shared, transport) = (shared.clone(), transport.clone());
        supervise::supervise("control channel", move || {
            ipc_server::serve(shared.clone(), transport.clone(), control.clone())
        });
    }
    {
        let shared = shared.clone();
        supervise::supervise("kill-switch ticker", move || {
            let shared = shared.clone();
            async move {
                let mut t = tokio::time::interval(Duration::from_secs(1));
                loop {
                    t.tick().await;
                    lock(&shared).tick();
                }
            }
        });
    }

    shutdown.await;
    // Going down is a node drop: take our rooms with us, loudly.
    lock(&shared).nuke_all("node shut down");
    tokio::time::sleep(Duration::from_millis(300)).await;
    Ok(())
}
