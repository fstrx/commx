//! commxd: the commx node daemon. Runs in the background, holds keys and
//! rooms in memory, talks to peers over Noise and to the local TUI over a
//! private unix socket (Windows: named pipe). All logic lives in the library.

// Every freed heap block is wiped, so plaintext doesn't outlive its use.
#[global_allocator]
static ALLOC: commx_core::secmem::ZeroizingAlloc = commx_core::secmem::ZeroizingAlloc;

use anyhow::Result;
use clap::Parser;
use commx_core::local_ipc;
use std::path::PathBuf;

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
    /// Don't use the UDP voice fast path (e.g. UDP is blocked); calls use TCP.
    #[arg(long)]
    no_udp: bool,
    /// Windows: relaunch in the background with no console window.
    #[cfg(windows)]
    #[arg(long)]
    detach: bool,
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
    commxd::install_panic_hook();
    let args = Args::parse();
    #[cfg(windows)]
    if args.detach {
        return detach();
    }
    let data_dir = args.data_dir.unwrap_or_else(commx_core::default_data_dir);
    let endpoint = args.socket.clone().unwrap_or_else(|| local_ipc::default_endpoint(&data_dir));
    let cfg = commxd::Config {
        data_dir,
        listen: args.listen,
        advertise: args.advertise,
        keep_awake: !args.no_keep_awake,
        tor: args.tor,
        tor_bin: args.tor_bin,
        no_udp: args.no_udp,
    };
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        if let Err(e) = shutdown_signal().await {
            eprintln!("commxd: signal handling unavailable: {e}");
            return std::future::pending::<()>().await;
        }
        let _ = stop_tx.send(());
    });
    commxd::run(cfg, commxd::Control::Endpoint(endpoint), async {
        let _ = stop_rx.await;
    })
    .await
}
