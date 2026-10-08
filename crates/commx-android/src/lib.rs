//! Android bridge: runs the commx daemon and voice engine inside the app
//! process and exposes them to Kotlin over JNI.
//!
//! The app speaks exactly the same newline-delimited JSON protocol as the
//! TUI (`commx_core::ipc`), over an in-memory pipe instead of a socket, so
//! there is no listening control endpoint for other apps to find. Voice
//! frames never cross into the JVM: `voice_in` events are routed straight to
//! the Rust voice engine and microphone frames go straight to the daemon.
//!
//! [`Bridge`] holds all the logic and is testable on desktop; the
//! `Java_...` functions at the bottom are thin JNI wrappers that also stop
//! panics from unwinding into the JVM.

// Every freed heap block is wiped, as in the desktop binaries.
#[global_allocator]
static ALLOC: commx_core::secmem::ZeroizingAlloc = commx_core::secmem::ZeroizingAlloc;

use anyhow::{anyhow, Result};
use commx_core::secmem::ZLines;
use commx_voice::{DeviceChoice, VoiceEngine};
use std::path::PathBuf;
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, oneshot};

const PIPE_BUF: usize = 256 * 1024;
const MAX_LINE: usize = 4 * 1024 * 1024;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Live audio numbers for the UI (meters, speaking indicator).
#[derive(Default, Clone)]
pub struct AudioState {
    pub active: bool,
    pub level: f32,
    pub speaking: Vec<String>,
}

enum VoiceCmd {
    Start { muted: bool, devices: DeviceChoice, reply: std_mpsc::Sender<Result<(), String>> },
    Stop,
    Mute(bool),
    Push { from: String, seq: u64, opus: Vec<u8> },
}

/// One running commx node plus its voice engine.
pub struct Bridge {
    rt: tokio::runtime::Runtime,
    to_daemon: mpsc::UnboundedSender<String>,
    events: Mutex<std_mpsc::Receiver<String>>,
    stop: Mutex<Option<oneshot::Sender<()>>>,
    node: Mutex<Option<tokio::task::JoinHandle<Result<()>>>>,
    voice: std_mpsc::Sender<VoiceCmd>,
    call_room: Arc<Mutex<Option<String>>>,
    audio: Arc<Mutex<AudioState>>,
}

pub struct StartOptions {
    pub data_dir: PathBuf,
    pub listen: String,
    pub no_udp: bool,
}

impl Bridge {
    pub fn start(opts: StartOptions) -> Result<Self> {
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().worker_threads(2).build()?;

        // The single UI client's pipe into the daemon.
        let (clients_tx, clients_rx) = mpsc::unbounded_channel();
        let (ui_end, daemon_end) = tokio::io::duplex(PIPE_BUF);
        let (dr, dw) = tokio::io::split(daemon_end);
        clients_tx
            .send((Box::new(dr) as commxd::Reader, Box::new(dw) as commxd::Writer))
            .map_err(|_| anyhow!("daemon control channel closed"))?;
        // Keep the sender alive for the daemon's lifetime (dropping it would
        // end the in-process accept loop); it's moved into the node task.
        let (ur, mut uw) = tokio::io::split(ui_end);

        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let cfg = commxd::Config {
            data_dir: opts.data_dir,
            listen: opts.listen,
            advertise: None,
            // Android: the app holds a wake lock; no caffeinate/systemd here.
            keep_awake: false,
            tor: false,
            tor_bin: String::new(),
            no_udp: opts.no_udp,
            web_dir: None,
        };
        let node = rt.spawn(async move {
            let _keep = clients_tx;
            commxd::run(cfg, commxd::Control::InProcess(clients_rx), async {
                let _ = stop_rx.await;
            })
            .await
        });

        // UI → daemon: request lines.
        let (to_daemon, mut req_rx) = mpsc::unbounded_channel::<String>();
        rt.spawn(async move {
            while let Some(mut line) = req_rx.recv().await {
                line.push('\n');
                if uw.write_all(line.as_bytes()).await.is_err() {
                    break;
                }
            }
        });

        // Voice engine lives on its own thread (audio streams aren't Send everywhere).
        let (mic_tx, mut mic_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (voice_tx, voice_rx) = std_mpsc::channel::<VoiceCmd>();
        let audio = Arc::new(Mutex::new(AudioState::default()));
        {
            let audio = audio.clone();
            std::thread::Builder::new()
                .name("commx-voice".into())
                .spawn(move || voice_thread(voice_rx, mic_tx, audio))?;
        }

        // Microphone frames → daemon, for whichever call we're in.
        let call_room: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        {
            let (to_daemon, call_room) = (to_daemon.clone(), call_room.clone());
            rt.spawn(async move {
                while let Some(pkt) = mic_rx.recv().await {
                    let room = lock(&call_room).clone();
                    if let Some(room_id) = room {
                        let req = serde_json::json!({"op": "voice_out", "room_id": room_id, "opus": hex::encode(pkt)});
                        let _ = to_daemon.send(req.to_string());
                    }
                }
            });
        }

        // Daemon → UI: events, except audio, which goes to the voice engine.
        let (ev_tx, ev_rx) = std_mpsc::channel::<String>();
        {
            let (voice_tx, call_room) = (voice_tx.clone(), call_room.clone());
            rt.spawn(async move {
                let mut lines = ZLines::new(ur, MAX_LINE);
                while let Ok(Some(line)) = lines.next_line().await {
                    let Ok(text) = std::str::from_utf8(&line) else { continue };
                    if text.starts_with("{\"ev\":\"voice_in\"") {
                        if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
                            let ours = lock(&call_room).as_deref() == v["room_id"].as_str();
                            if let (true, Some(from), Some(seq), Some(Ok(opus))) = (
                                ours,
                                v["from"].as_str(),
                                v["seq"].as_u64(),
                                v["opus"].as_str().map(hex::decode),
                            ) {
                                let _ = voice_tx.send(VoiceCmd::Push { from: from.to_string(), seq, opus });
                            }
                        }
                        continue;
                    }
                    if ev_tx.send(text.to_string()).is_err() {
                        break;
                    }
                }
            });
        }

        Ok(Self {
            rt,
            to_daemon,
            events: Mutex::new(ev_rx),
            stop: Mutex::new(Some(stop_tx)),
            node: Mutex::new(Some(node)),
            voice: voice_tx,
            call_room,
            audio,
        })
    }

    /// Send one IPC request (JSON object, no newline).
    pub fn send(&self, json: &str) -> Result<()> {
        if json.contains('\n') {
            return Err(anyhow!("request must be a single line"));
        }
        self.to_daemon.send(json.to_string()).map_err(|_| anyhow!("daemon stopped"))
    }

    /// Next event line, waiting up to `timeout`.
    pub fn next_event(&self, timeout: Duration) -> Option<String> {
        lock(&self.events).recv_timeout(timeout).ok()
    }

    /// Open mic + speakers for the call in `room_id`.
    pub fn voice_start(&self, room_id: &str, muted: bool) -> Result<()> {
        let (reply, rx) = std_mpsc::channel();
        self.voice
            .send(VoiceCmd::Start { muted, devices: DeviceChoice::default(), reply })
            .map_err(|_| anyhow!("voice engine stopped"))?;
        rx.recv_timeout(Duration::from_secs(10)).map_err(|_| anyhow!("audio didn't start"))?.map_err(|e| anyhow!(e))?;
        *lock(&self.call_room) = Some(room_id.to_string());
        Ok(())
    }

    pub fn voice_stop(&self) {
        *lock(&self.call_room) = None;
        let _ = self.voice.send(VoiceCmd::Stop);
    }

    pub fn voice_mute(&self, muted: bool) {
        let _ = self.voice.send(VoiceCmd::Mute(muted));
    }

    pub fn audio_state(&self) -> AudioState {
        lock(&self.audio).clone()
    }

    /// Stop the node: every room is nuked (and peers told) before returning.
    pub fn stop(self) {
        self.voice_stop();
        if let Some(tx) = lock(&self.stop).take() {
            let _ = tx.send(());
        }
        if let Some(node) = lock(&self.node).take() {
            let _ = self.rt.block_on(async { tokio::time::timeout(Duration::from_secs(3), node).await });
        }
        self.rt.shutdown_timeout(Duration::from_secs(1));
    }
}

fn voice_thread(rx: std_mpsc::Receiver<VoiceCmd>, mic: mpsc::UnboundedSender<Vec<u8>>, audio: Arc<Mutex<AudioState>>) {
    let mut engine: Option<VoiceEngine> = None;
    loop {
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(VoiceCmd::Start { muted, devices, reply }) => {
                engine = None;
                match VoiceEngine::start(mic.clone(), muted, devices).map_err(|e| format!("{e:#}")) {
                    Ok(e) => {
                        engine = Some(e);
                        let _ = reply.send(Ok(()));
                    }
                    Err(e) => {
                        let _ = reply.send(Err(e));
                    }
                }
            }
            Ok(VoiceCmd::Stop) => engine = None,
            Ok(VoiceCmd::Mute(m)) => {
                if let Some(e) = &engine {
                    e.set_muted(m);
                }
            }
            Ok(VoiceCmd::Push { from, seq, opus }) => {
                if let Some(e) = &engine {
                    e.push(&from, seq, opus);
                }
            }
            Err(std_mpsc::RecvTimeoutError::Timeout) => {}
            Err(std_mpsc::RecvTimeoutError::Disconnected) => break,
        }
        let mut a = lock(&audio);
        match &engine {
            Some(e) => {
                a.active = true;
                a.level = e.mic_level();
                a.speaking = e.speaking();
            }
            None => *a = AudioState::default(),
        }
    }
}

// ---------------------------------------------------------------- JNI ----

mod jni_api {
    use super::*;
    use jni::objects::{JClass, JObject, JString};
    use jni::sys::{jboolean, jlong, jstring, JNI_TRUE};
    use jni::JNIEnv;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::OnceLock;

    static BRIDGE: Mutex<Option<Arc<Bridge>>> = Mutex::new(None);

    fn bridge() -> Option<Arc<Bridge>> {
        lock(&BRIDGE).clone()
    }

    /// Run `f`, turning panics into `None` so they never cross into the JVM.
    fn guard<T>(f: impl FnOnce() -> T) -> Option<T> {
        catch_unwind(AssertUnwindSafe(f)).ok()
    }

    fn jstr(env: &mut JNIEnv, s: &JString) -> String {
        env.get_string(s).map(|s| s.into()).unwrap_or_default()
    }

    fn out(env: &mut JNIEnv, s: Option<String>) -> jstring {
        match s {
            Some(s) => env.new_string(s).map(|j| j.into_raw()).unwrap_or(std::ptr::null_mut()),
            None => std::ptr::null_mut(),
        }
    }

    #[cfg(target_os = "android")]
    fn init_android_context(env: &mut JNIEnv, context: &JObject) -> Result<()> {
        static DONE: OnceLock<()> = OnceLock::new();
        if DONE.get().is_some() {
            return Ok(());
        }
        let vm = env.get_java_vm()?;
        let ctx = env.new_global_ref(context)?;
        // cpal's AAudio backend needs the JavaVM + Context (audio routing).
        unsafe { ndk_context::initialize_android_context(vm.get_java_vm_pointer().cast(), ctx.as_obj().as_raw().cast()) };
        std::mem::forget(ctx); // must outlive the process
        let _ = DONE.set(());
        Ok(())
    }

    #[cfg(not(target_os = "android"))]
    fn init_android_context(_env: &mut JNIEnv, _context: &JObject) -> Result<()> {
        let _ = OnceLock::<()>::new();
        Ok(())
    }

    /// Returns null on success, else an error message.
    #[no_mangle]
    pub extern "system" fn Java_io_github_fstrx_commx_NativeBridge_start<'l>(
        mut env: JNIEnv<'l>,
        _class: JClass<'l>,
        context: JObject<'l>,
        data_dir: JString<'l>,
        listen: JString<'l>,
        no_udp: jboolean,
    ) -> jstring {
        let data_dir = jstr(&mut env, &data_dir);
        let listen = jstr(&mut env, &listen);
        let res = guard(|| -> Result<()> {
            if bridge().is_some() {
                return Ok(());
            }
            commx_core::secmem::harden_process();
            commxd::install_panic_hook();
            init_android_context(&mut env, &context)?;
            let b = Bridge::start(StartOptions { data_dir: data_dir.into(), listen, no_udp: no_udp == JNI_TRUE })?;
            *lock(&BRIDGE) = Some(Arc::new(b));
            Ok(())
        });
        let err = match res {
            Some(Ok(())) => None,
            Some(Err(e)) => Some(format!("{e:#}")),
            None => Some("internal error".into()),
        };
        out(&mut env, err)
    }

    #[no_mangle]
    pub extern "system" fn Java_io_github_fstrx_commx_NativeBridge_send<'l>(
        mut env: JNIEnv<'l>,
        _class: JClass<'l>,
        json: JString<'l>,
    ) -> jstring {
        let json = jstr(&mut env, &json);
        let err = guard(|| bridge().map(|b| b.send(&json))).flatten().and_then(|r| r.err()).map(|e| e.to_string());
        out(&mut env, err)
    }

    /// Next event JSON, or null on timeout / not running.
    #[no_mangle]
    pub extern "system" fn Java_io_github_fstrx_commx_NativeBridge_nextEvent<'l>(
        mut env: JNIEnv<'l>,
        _class: JClass<'l>,
        timeout_ms: jlong,
    ) -> jstring {
        let ev = guard(|| bridge().and_then(|b| b.next_event(Duration::from_millis(timeout_ms.max(0) as u64)))).flatten();
        out(&mut env, ev)
    }

    #[no_mangle]
    pub extern "system" fn Java_io_github_fstrx_commx_NativeBridge_voiceStart<'l>(
        mut env: JNIEnv<'l>,
        _class: JClass<'l>,
        room_id: JString<'l>,
        muted: jboolean,
    ) -> jstring {
        let room_id = jstr(&mut env, &room_id);
        let err = match guard(|| bridge().map(|b| b.voice_start(&room_id, muted == JNI_TRUE))) {
            Some(Some(Ok(()))) => None,
            Some(Some(Err(e))) => Some(format!("{e:#}")),
            Some(None) => Some("not running".into()),
            None => Some("internal error".into()),
        };
        out(&mut env, err)
    }

    #[no_mangle]
    pub extern "system" fn Java_io_github_fstrx_commx_NativeBridge_voiceStop<'l>(_env: JNIEnv<'l>, _class: JClass<'l>) {
        guard(|| bridge().map(|b| b.voice_stop()));
    }

    #[no_mangle]
    pub extern "system" fn Java_io_github_fstrx_commx_NativeBridge_voiceMute<'l>(
        _env: JNIEnv<'l>,
        _class: JClass<'l>,
        muted: jboolean,
    ) {
        guard(|| bridge().map(|b| b.voice_mute(muted == JNI_TRUE)));
    }

    /// `{"active":bool,"level":f32,"speaking":[names]}`
    #[no_mangle]
    pub extern "system" fn Java_io_github_fstrx_commx_NativeBridge_audioState<'l>(
        mut env: JNIEnv<'l>,
        _class: JClass<'l>,
    ) -> jstring {
        let s = guard(|| {
            let a = bridge().map(|b| b.audio_state()).unwrap_or_default();
            serde_json::json!({"active": a.active, "level": a.level, "speaking": a.speaking}).to_string()
        });
        out(&mut env, s)
    }

    /// Nukes every room (peers are told) and stops the node.
    #[no_mangle]
    pub extern "system" fn Java_io_github_fstrx_commx_NativeBridge_stop<'l>(_env: JNIEnv<'l>, _class: JClass<'l>) {
        guard(|| {
            if let Some(b) = lock(&BRIDGE).take() {
                if let Ok(b) = Arc::try_unwrap(b) {
                    b.stop();
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wait(b: &Bridge, what: &str, pred: impl Fn(&serde_json::Value) -> bool) -> serde_json::Value {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while std::time::Instant::now() < deadline {
            if let Some(line) = b.next_event(Duration::from_millis(200)) {
                let v: serde_json::Value = serde_json::from_str(&line).unwrap();
                if pred(&v) {
                    return v;
                }
            }
        }
        panic!("timed out waiting for {what}");
    }

    /// The embedded daemon speaks the normal protocol over the in-process pipe.
    #[test]
    fn embedded_node_round_trip() {
        let dir = std::env::temp_dir().join(format!("cx-android-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let b = Bridge::start(StartOptions { data_dir: dir.clone(), listen: "127.0.0.1:0".into(), no_udp: true }).unwrap();
        b.send(r#"{"op":"alias_new","name":"droid","ephemeral":true,"passphrase":null}"#).unwrap();
        let v = wait(&b, "status", |v| v["ev"] == "status");
        assert_eq!(v["alias"], "droid");
        b.send(r#"{"op":"room_new","name":"r","kill_mode":"HostOnly","grace_secs":15,"dm":false}"#).unwrap();
        let inv = wait(&b, "invite", |v| v["ev"] == "invite_code");
        assert!(inv["code"].as_str().unwrap().starts_with("cx1:"));
        assert!(b.send("{\n}").is_err(), "multi-line requests rejected");
        assert!(!b.audio_state().active);
        b.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
