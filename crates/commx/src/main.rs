//! commx: terminal client for the commx daemon.

// Every freed heap block is wiped, so plaintext doesn't outlive its use.
#[global_allocator]
static ALLOC: commx_core::secmem::ZeroizingAlloc = commx_core::secmem::ZeroizingAlloc;

mod app;
mod commands;
mod ui;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use commx_core::ipc::{IpcEvent, IpcRequest};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use std::path::PathBuf;
use std::time::Duration;
use commx_core::secmem::ZLines;
use tokio::io::AsyncWriteExt;
use tokio::net::unix::OwnedWriteHalf;
use tokio::net::UnixStream;
use tokio::sync::mpsc;

use app::App;

#[derive(Parser)]
#[command(name = "commx", about = "private P2P chat — terminal client")]
struct Args {
    /// commxd control socket [default: <data-dir>/commxd.sock]
    #[arg(long)]
    socket: Option<PathBuf>,
    #[arg(long)]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Panic button: destroy every room on this node right now.
    Nuke,
}

async fn send(w: &mut OwnedWriteHalf, req: &IpcRequest) -> Result<()> {
    let mut line = serde_json::to_vec(req)?;
    line.push(b'\n');
    w.write_all(&line).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    commx_core::secmem::harden_process();
    let args = Args::parse();
    let sock = args
        .socket
        .unwrap_or_else(|| args.data_dir.unwrap_or_else(commx_core::default_data_dir).join("commxd.sock"));
    let stream = UnixStream::connect(&sock)
        .await
        .with_context(|| format!("can't reach commxd at {} — is the daemon running?", sock.display()))?;
    let (r, mut w) = stream.into_split();

    let (ev_tx, mut ev_rx) = mpsc::unbounded_channel::<IpcEvent>();
    tokio::spawn(async move {
        let mut lines = ZLines::new(r, 4 * 1024 * 1024);
        while let Ok(Some(line)) = lines.next_line().await {
            if let Ok(ev) = serde_json::from_slice(&line) {
                if ev_tx.send(ev).is_err() {
                    break;
                }
            }
        }
    });

    if let Some(Cmd::Nuke) = args.cmd {
        send(&mut w, &IpcRequest::Nuke { room_id: None }).await?;
        loop {
            match tokio::time::timeout(Duration::from_secs(5), ev_rx.recv()).await {
                Ok(Some(IpcEvent::Ok { msg })) => {
                    println!("{msg}");
                    return Ok(());
                }
                Ok(Some(IpcEvent::Nuked { name, .. })) => println!("nuked #{name}"),
                Ok(Some(_)) => {}
                _ => bail!("daemon didn't confirm"),
            }
        }
    }

    // Keys come from a blocking thread; crossterm's reader isn't async.
    let (key_tx, mut key_rx) = mpsc::unbounded_channel::<Event>();
    std::thread::spawn(move || {
        while let Ok(ev) = event::read() {
            if key_tx.send(ev).is_err() {
                break;
            }
        }
    });

    send(&mut w, &IpcRequest::Status).await?;
    let mut terminal = ratatui::init();
    let mut app = App::new();
    let result: Result<()> = async {
        loop {
            terminal.draw(|f| ui::draw(f, &app))?;
            let reqs = tokio::select! {
                ev = ev_rx.recv() => match ev {
                    Some(ev) => app.on_event(ev),
                    None => bail!("daemon connection closed"),
                },
                Some(ev) = key_rx.recv() => on_input(&mut app, ev),
            };
            for req in reqs {
                send(&mut w, &req).await?;
            }
            if app.quit {
                return Ok(());
            }
        }
    }
    .await;
    ratatui::restore();
    result
}

fn on_input(app: &mut App, ev: Event) -> Vec<IpcRequest> {
    let Event::Key(k) = ev else { return Vec::new() };
    if k.kind != KeyEventKind::Press {
        return Vec::new();
    }
    let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
    match k.code {
        KeyCode::Char('c') | KeyCode::Char('q') if ctrl => app.quit = true,
        KeyCode::Char('u') if ctrl => app.input.clear(),
        KeyCode::Esc if app.secret.is_some() => {
            app.secret = None;
            app.input.clear();
        }
        KeyCode::Enter => return app.submit(),
        KeyCode::Tab => app.cycle(true),
        KeyCode::BackTab => app.cycle(false),
        KeyCode::PageUp => app.scroll += 5,
        KeyCode::PageDown => app.scroll = app.scroll.saturating_sub(5),
        KeyCode::Backspace => {
            app.input.pop();
        }
        KeyCode::Char(c) => app.input.push(c),
        _ => {}
    }
    Vec::new()
}
