//! commxd: the commx node. Runs in the background, holds keys and rooms in
//! memory, talks to peers over Noise and to the local TUI over a unix socket.

// Every freed heap block is wiped, so plaintext doesn't outlive its use.
#[global_allocator]
static ALLOC: commx_core::secmem::ZeroizingAlloc = commx_core::secmem::ZeroizingAlloc;

mod ipc_server;
mod killswitch;
mod net;
mod power;
mod state;
mod transport;

use anyhow::{bail, Context, Result};
use clap::Parser;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::Semaphore;

/// Connections allowed in the handshake/join phase at once.
const MAX_PREAUTH: usize = 32;

use state::{lock, Daemon, Shared};
use transport::{Net, NodeKey};

#[derive(Parser)]
#[command(name = "commxd", about = "commx node daemon")]
struct Args {
    /// Where encrypted alias files live (nothing else is ever written).
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// Control socket path [default: <data-dir>/commxd.sock]
    #[arg(long)]
    socket: Option<PathBuf>,
    /// Address to accept peers on.
    #[arg(long, default_value = "0.0.0.0:4700")]
    listen: String,
    /// Address put in invites, if peers reach you differently (port forward, Tailscale IP...).
    #[arg(long)]
    advertise: Option<String>,
    /// Don't hold a sleep inhibitor while rooms are live.
    #[arg(long)]
    no_keep_awake: bool,
    /// Route everything over Tor: each room gets its own onion address and
    /// peers never see your IP. Launches a private tor process.
    #[arg(long)]
    tor: bool,
    /// tor executable to launch in --tor mode.
    #[arg(long, default_value = "tor")]
    tor_bin: String,
}

fn private_dir(p: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(p)?;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))?;
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

fn bind_socket(path: &Path) -> Result<UnixListener> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        // Only ever delete a stale socket, never some other file.
        if !meta.file_type().is_socket() {
            bail!("{} exists and is not a socket", path.display());
        }
        if std::os::unix::net::UnixStream::connect(path).is_ok() {
            bail!("commxd already running on {}", path.display());
        }
        std::fs::remove_file(path)?;
    }
    let l = UnixListener::bind(path).with_context(|| format!("bind {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(l)
}

#[tokio::main]
async fn main() -> Result<()> {
    commx_core::secmem::harden_process();
    let args = Args::parse();
    let data_dir = args.data_dir.unwrap_or_else(commx_core::default_data_dir);
    private_dir(&data_dir)?;
    let sock_path = args.socket.unwrap_or_else(|| data_dir.join("commxd.sock"));
    // Create a missing parent privately, but never chmod an existing directory
    // (it might be /tmp). The socket itself is 0600 and peer-UID checked.
    if let Some(parent) = sock_path.parent().filter(|p| !p.as_os_str().is_empty() && !p.exists()) {
        private_dir(parent)?;
    }
    let ipc = bind_socket(&sock_path)?;

    // In Tor mode only tor itself may reach us, so listen on loopback.
    let listen = if args.tor { "127.0.0.1:0".to_string() } else { args.listen.clone() };
    let tcp = TcpListener::bind(&listen).await.with_context(|| format!("listen on {listen}"))?;
    let bound: SocketAddr = tcp.local_addr()?;
    let key = NodeKey::generate()?;
    let transport = if args.tor {
        let net = Arc::new(Net::tor(key, bound.port()));
        let tor_dir = data_dir.join("tor");
        private_dir(&tor_dir)?;
        net.start_tor(args.tor_bin.clone(), tor_dir);
        net
    } else {
        let advertise = args.advertise.clone().unwrap_or_else(|| {
            let ip = if bound.ip().is_unspecified() { guess_ip() } else { bound.ip() };
            SocketAddr::new(ip, bound.port()).to_string()
        });
        Arc::new(Net::tcp(key, bound.port(), advertise))
    };

    let shared: Shared = Arc::new(Mutex::new(Daemon::new(data_dir, transport.clone(), !args.no_keep_awake)));
    eprintln!("commxd up: {} · control socket {}", transport.label(), sock_path.display());

    {
        let (shared, transport) = (shared.clone(), transport.clone());
        let preauth = Arc::new(Semaphore::new(MAX_PREAUTH));
        tokio::spawn(async move {
            loop {
                if let Ok(stream) = transport.accept(&tcp).await {
                    // Shed load instead of queueing unauthenticated strangers.
                    let Ok(permit) = preauth.clone().try_acquire_owned() else { continue };
                    tokio::spawn(net::handle_inbound(shared.clone(), transport.clone(), stream, permit));
                }
            }
        });
    }
    tokio::spawn(ipc_server::serve(shared.clone(), transport.clone(), ipc));
    {
        let shared = shared.clone();
        tokio::spawn(async move {
            let mut t = tokio::time::interval(Duration::from_secs(1));
            loop {
                t.tick().await;
                lock(&shared).tick();
            }
        });
    }

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
    // Going down is a node drop: take our rooms with us, loudly.
    lock(&shared).nuke_all("node shut down");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let _ = std::fs::remove_file(&sock_path);
    Ok(())
}
