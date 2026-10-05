//! commx: terminal client for the commx daemon.

// Every freed heap block is wiped, so plaintext doesn't outlive its use.
#[global_allocator]
static ALLOC: commx_core::secmem::ZeroizingAlloc = commx_core::secmem::ZeroizingAlloc;

mod app;
mod codec;
mod commands;
mod dsp;
mod ui;
mod voice;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use commx_core::ipc::{IpcEvent, IpcRequest};
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use std::path::PathBuf;
use std::time::Duration;
use commx_core::secmem::ZLines;
use tokio::io::AsyncWriteExt;
use commx_core::local_ipc::{self, Writer};
use tokio::sync::mpsc;

use app::App;

#[derive(Parser)]
#[command(name = "commx", about = "private P2P chat — terminal client")]
struct Args {
    /// commxd control endpoint: socket path, or pipe name on Windows [default: per data dir]
    #[arg(long)]
    socket: Option<String>,
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

async fn send(w: &mut Writer, req: &IpcRequest) -> Result<()> {
    let mut line = serde_json::to_vec(req)?;
    line.push(b'\n');
    w.write_all(&line).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    commx_core::secmem::harden_process();
    let args = Args::parse();
    let endpoint = args.socket.unwrap_or_else(|| {
        local_ipc::default_endpoint(&args.data_dir.unwrap_or_else(commx_core::default_data_dir))
    });
    let (r, mut w) = local_ipc::connect(&endpoint)
        .await
        .with_context(|| format!("can't reach commxd at {endpoint} — is the daemon running?"))?;

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
    // Refresh status (tor bootstrap, keep-awake) periodically.
    let mut refresh = tokio::time::interval(Duration::from_secs(3));
    // Encoded microphone frames from the audio thread.
    let (mic_tx, mut mic_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let mut engine: Option<(String, voice::VoiceEngine)> = None;
    // Don't retry opening devices for a call we just bailed out of.
    let mut audio_failed: Option<String> = None;
    let mut redraw = true;
    let result: Result<()> = async {
        loop {
            if redraw {
                terminal.draw(|f| ui::draw(f, &app))?;
            }
            redraw = true;
            let mut reqs = tokio::select! {
                _ = refresh.tick() => vec![IpcRequest::Status],
                ev = ev_rx.recv() => match ev {
                    Some(IpcEvent::VoiceIn { room_id, from, seq, opus }) => {
                        redraw = false;
                        if let (Some((r, e)), Ok(pkt)) = (&engine, hex::decode(&opus)) {
                            if *r == room_id {
                                e.push(&from, seq, pkt);
                            }
                        }
                        Vec::new()
                    }
                    Some(ev) => app.on_event(ev),
                    None => bail!("daemon connection closed"),
                },
                Some(pkt) = mic_rx.recv() => {
                    redraw = false;
                    match &engine {
                        Some((room_id, _)) => vec![IpcRequest::VoiceOut { room_id: room_id.clone(), opus: hex::encode(pkt) }],
                        None => Vec::new(),
                    }
                }
                Some(ev) = key_rx.recv() => on_input(&mut app, ev),
            };
            // Audio follows the daemon's roster: open devices when we're in a
            // call, close them (and drop all buffered audio) when we're not.
            let want = app.call_room();
            if want.is_none() {
                audio_failed = None;
            }
            if engine.as_ref().map(|(r, _)| r) != want.as_ref() && audio_failed != want {
                engine = None;
                if let Some(room_id) = want {
                    match voice::VoiceEngine::start(mic_tx.clone(), app.muted) {
                        Ok(e) => engine = Some((room_id, e)),
                        Err(e) => {
                            app.on_event(IpcEvent::Error { msg: format!("audio: {e:#}") });
                            audio_failed = Some(room_id.clone());
                            reqs.push(IpcRequest::Hangup { room_id });
                        }
                    }
                }
            }
            if let Some((_, e)) = &engine {
                e.set_muted(app.muted);
            }
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
