//! commxd: the commx node. Runs in the background, holds keys and rooms in
//! memory, talks to peers over Noise and to the local TUI over a private
//! unix socket (Windows: named pipe).

// Every freed heap block is wiped, so plaintext doesn't outlive its use.
#[global_allocator]
static ALLOC: commx_core::secmem::ZeroizingAlloc = commx_core::secmem::ZeroizingAlloc;

mod files;
mod ipc_server;
mod killswitch;
mod net;
mod power;
mod state;
mod transport;

use anyhow::{Context, Result};
use clap::Parser;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use commx_core::local_ipc;
use tokio::net::TcpListener;
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
    /// Control endpoint: socket path, or pipe name on Windows [default: per data dir]
    #[arg(long)]
    socket: Option<String>,
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
    /// Windows: relaunch in the background with no console window.
    #[cfg(windows)]
    #[arg(long)]
    detach: bool,
}

/// Create a directory only we can read. On Windows, the user profile's
/// inherited ACL already restricts it to the user.
fn private_dir(p: &Path) -> Result<()> {
    std::fs::create_dir_all(p)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(windows)]
    {
        use tokio::signal::windows;
        let (mut close, mut shutdown, mut logoff) = (windows::ctrl_close()?, windows::ctrl_shutdown()?, windows::ctrl_logoff()?);
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = close.recv() => {}
            _ = shutdown.recv() => {}
            _ = logoff.recv() => {}
        }
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

/// Re-run ourselves without `--detach`, with no console, and exit.
#[cfg(windows)]
fn detach() -> Result<()> {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let args: Vec<String> = std::env::args().skip(1).filter(|a| a != "--detach").collect();
    std::process::Command::new(std::env::current_exe()?)
        .args(args)
        .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    commx_core::secmem::harden_process();
    let args = Args::parse();
    #[cfg(windows)]
    if args.detach {
        return detach();
    }
    let data_dir = args.data_dir.unwrap_or_else(commx_core::default_data_dir);
    private_dir(&data_dir)?;
    let endpoint = args.socket.clone().unwrap_or_else(|| local_ipc::default_endpoint(&data_dir));
    // Create a missing socket parent privately, but never chmod an existing
    // directory (it might be /tmp). The socket itself is 0600 and peer-UID checked.
    #[cfg(unix)]
    if let Some(parent) = Path::new(&endpoint).parent().filter(|p| !p.as_os_str().is_empty() && !p.exists()) {
        private_dir(parent)?;
    }
    let ipc = local_ipc::Listener::bind(&endpoint).with_context(|| format!("control endpoint {endpoint}"))?;
    files::purge_orphans(&data_dir);

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
    eprintln!("commxd up: {} · control {endpoint}", transport.label());

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

    shutdown_signal().await?;
    // Going down is a node drop: take our rooms with us, loudly.
    lock(&shared).nuke_all("node shut down");
    tokio::time::sleep(Duration::from_millis(300)).await;
    Ok(())
}
