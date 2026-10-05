//! commxd: the commx node. Runs in the background, holds keys and rooms in
//! memory, talks to peers over Noise and to the local TUI over a unix socket.

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

use state::{lock, Daemon, Shared};
use transport::tcp::TcpTransport;
use transport::NodeKey;

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
}

/// No core dumps (they'd contain keys), no ptrace attach on Linux.
fn harden() {
    unsafe {
        let zero = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &zero);
        #[cfg(target_os = "linux")]
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
    }
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
    use std::os::unix::fs::PermissionsExt;
    if path.exists() {
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
    harden();
    let args = Args::parse();
    let data_dir = args.data_dir.unwrap_or_else(commx_core::default_data_dir);
    private_dir(&data_dir)?;
    let sock_path = args.socket.unwrap_or_else(|| data_dir.join("commxd.sock"));
    if let Some(parent) = sock_path.parent() {
        private_dir(parent)?;
    }
    let ipc = bind_socket(&sock_path)?;

    let tcp = TcpListener::bind(&args.listen).await.with_context(|| format!("listen on {}", args.listen))?;
    let bound: SocketAddr = tcp.local_addr()?;
    let advertise = args.advertise.unwrap_or_else(|| {
        let ip = if bound.ip().is_unspecified() { guess_ip() } else { bound.ip() };
        SocketAddr::new(ip, bound.port()).to_string()
    });

    let shared: Shared = Arc::new(Mutex::new(Daemon::new(data_dir, advertise.clone(), !args.no_keep_awake)));
    let transport = Arc::new(TcpTransport { key: Arc::new(NodeKey::generate()?) });
    eprintln!("commxd listening on {bound} (invites use {advertise}), control socket {}", sock_path.display());

    {
        let (shared, transport) = (shared.clone(), transport.clone());
        tokio::spawn(async move {
            loop {
                if let Ok(stream) = transport.accept(&tcp).await {
                    tokio::spawn(net::handle_inbound(shared.clone(), transport.clone(), stream));
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
