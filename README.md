# commx

commx is peer-to-peer chat, voice calls and file sharing for small groups of friends. Everything is end-to-end encrypted. There are no servers, no accounts and no phone numbers, only aliases. Rooms self-destruct when nodes drop. It runs over Tor, or over direct TCP for a LAN or VPN.

```
 commx (TUI) ──private socket / pipe── commxd ──Noise_XX over TCP or Tor── other commxd nodes
```

- **`commxd`** is the node. It runs in the background, holds keys and rooms in locked memory, and talks to peers.
- **`commx`** is the terminal client. It talks only to your local `commxd`.

It runs on macOS, Linux, Windows and Android. Friends without the app can join from a web browser.

## Install

### macOS / Linux

Building from source needs Rust and `cmake` (for the bundled Opus codec). On Linux you also need ALSA headers, e.g. `apt install cmake libasound2-dev`.

```sh
cargo install --path crates/commxd
cargo install --path crates/commx
commxd --tor &        # or without --tor on a LAN/VPN; launchd/systemd units in dist/
commx
```

Tor mode needs a `tor` binary on your PATH. On macOS that's `brew install tor`; on Linux, `apt install tor` or similar.

### Windows

1. Get `commx-windows-x86_64.zip` from a release (built by CI), or build it yourself with `cargo build --release`.
2. Run `powershell -ExecutionPolicy Bypass -File install-windows.ps1`. This installs to `%LOCALAPPDATA%\commx`, starts `commxd` hidden at logon and adds `commx` to your PATH.
3. Open a new terminal (Windows Terminal recommended) and run `commx`.
4. For Tor mode, install the Tor Expert Bundle. Then add `--tor --tor-bin C:\path\to\tor.exe` to the `commxd` Startup shortcut.

### Android

Install `commx-android.apk` from a release (Android 8.0+, arm64 or x86_64). It's a native app built on the same Rust core: the daemon runs inside the app as a foreground service, and the UI is Jetpack Compose.
- **Layout:** two panes on tablets, one on phones. With a hardware keyboard, Enter sends and every `/command` from the TUI works.
- **Background:** the node keeps running with the screen off. While a room is open the app holds a wake lock and a Wi-Fi lock, because a sleeping node would trip the kill switch. "Quit & nuke all" in the notification shuts everything down.
- **Calls:** call, mute and hold-to-talk buttons. The microphone permission is requested the first time you call.
- **Privacy:**
  - Screenshots, screen recording and the recent-apps thumbnail are blocked.
  - No backups: nothing is in cloud or adb backups.
  - The notification never shows room names or messages.
  - Invites are copied as "sensitive", so clipboard previews hide them.
- **Not on Android yet:** Tor mode, and sending or saving files. Receiving still works.
- **Updates:** builds without a configured release key are signed with a throwaway key, and Android refuses to install an update signed with a different key. See [Develop](#develop) to set up a stable signing key.

### Web browser (join only)

The host runs `commxd --web web/ --web-tls` (release zips include `web/`; from source, run `web/build.sh` and pass `web/dist`). Every invite then also gets a browser link, `https://<host>:4700/#cx1:...`. Your friend opens it, picks an alias and is in the room: chat, files and voice calls.
- **The host's node serves the page.** The browser connects back to that node over a WebSocket, on the same port as normal peers.
- **Same protocol, same crypto.** The browser runs the commx protocol compiled to WebAssembly: the Noise handshake, the signed chain, room keys, file and call encryption. Everything is checked against the host fingerprint in the invite. The invite rides in the link's `#` part, which browsers never send to any server, and the page erases it from the address bar as soon as it's read.
- **`--web-tls`: HTTPS with a self-signed certificate,** made fresh in RAM each run. Browsers only allow the microphone over HTTPS, so voice needs it. Friends get a certificate warning the first time. The host's invite shows the certificate's SHA-256, so they can compare it with the one in the browser's certificate details before clicking through. Plain `http://` requests are redirected to `https://`. Without `--web-tls`, chat and files work, but calls don't.
- **Files.** Files are sent and received with the same chunk encryption and hash check as the apps. A received file stays decrypted in the tab's memory only (512 MiB for all files together) until you press Save or the room ends. Once you save it, the browser's download is an ordinary file on disk.
- **Voice.** Calls use Opus at 24 kb/s hard CBR in 20 ms frames, the same as the apps, through the browser's built-in WebCodecs, with constant-size frames sent continuously, silence included. This needs a current Chrome, Edge, Firefox or Safari. Use headphones to avoid echo.
- **Members only.** A web page can't accept connections, so browser users can join rooms but can't host them.
- **Nothing is stored.** The identity lives in RAM only.
- **Leaving.** Closing the tab leaves the room, and the kill switch applies. Background tabs stay connected because the client answers the host's heartbeats instead of relying on timers.
- **Trust.** Over plain `http://`, an attacker on the network between your friend and you could swap the page's code. `--web-tls` stops that, as long as the certificate fingerprint is checked. Otherwise use a LAN or VPN you trust, such as Tailscale. Or run the host with `--tor`, and the friend opens the onion link in Tor Browser, where the onion address itself authenticates the server.

## Use

```
/alias new ghost --ephemeral        RAM-only identity (drop --ephemeral to save it, passphrase-encrypted)
/room new lounge --any-member       host a room; prints a single-use invite (cx1:...)
/invite pw   /invite revoke         reusable invite that needs a password (cx2:...) / kill it
/join cx1:...                       join a friend's room (cx2: asks for the password)
/send ~/notes.pdf                   share a file (max 256 MiB)
/files   /save 1 [path]             list files / export a decrypted copy
/call    /hangup   /mute            start or join the room's voice call / leave / mute
/ptt     /echotest                  push-to-talk (hold Space) / hear yourself through the codec
/devices /mic 2  /speaker 1         list and pick audio devices
/nuke    /nuke all                  destroy this room / everything
```

**Invites.** A `cx1:` invite is single use and expires after 10 minutes. A `cx2:` invite can be used again and again until the room ends or you revoke it, but only with its password. Send the password over a different channel from the code. The password never crosses the network: joiners prove they know it with a key derived from it (Argon2id) and bound to the encrypted connection. They only send that proof after the host has proven, on the same connection, that it is the invite's host, so someone intercepting the connection gets nothing to guess against offline. Five wrong passwords in 10 minutes pause the invite, and the host sees every failed attempt.

Send invite codes over a channel you trust. Each side shows a fingerprint for the other (`[abcd-efgh-...]`); compare fingerprints once, out of band. Panic button from any shell: `commx nuke`.

## Network

- **`--tor` (recommended).** `commxd` launches its own private tor process, which exits with it.
  - **Room addresses:** every room gets its own onion address. The keys are discarded at creation and the onion is deleted on nuke.
  - **Outgoing connections:** each one uses its own circuit.
  - **No IP leaks:** peers never see your IP. Clearnet addresses are refused, and the listener binds to loopback only.
  - **Timing:** first bootstrap takes about 15–30s. A new room's onion takes up to a minute before friends can join.
- **Direct TCP (default).** Port 4700. Use this on a LAN, or over Tailscale/WireGuard with `--advertise 100.x.y.z:4700`, or with a port forward. Peers see each other's IP.
- **What a captured packet gives away.** Anyone on a shared network (a mesh neighbour, café Wi-Fi, an ISP) can record your traffic; no software can stop that. commx makes the recording useless:
  - **Encrypted twice:** each connection is a Noise channel with fresh keys, and messages inside are encrypted again under the room key, end to end.
  - **Frame padding:** every frame is padded to one of a few sizes (256 bytes, powers of two up to 4 KiB, then 4 KiB steps), so message lengths don't show.
  - **Forward secrecy:** channel keys re-key every 64 frames, and UDP voice keys every 30 s, with old keys erased. Seizing a node later doesn't unlock what was recorded earlier.
  - **No tampering or impersonation:** a malicious router or mesh node can drop or delay traffic, but can't read, alter or inject it. Invites pin the host's key, and every message is signed.
  - **Still visible:** timing, volume and, outside Tor, who connects to whom.
- **Wi-Fi mesh, no internet.** commx only needs IP between the nodes, so any mesh that provides it works unchanged, e.g. [batman-adv](https://www.open-mesh.org/projects/batman-adv/wiki) or 802.11s on Linux, or [Yggdrasil](https://yggdrasil-network.github.io/) on top of any link. Advertise the mesh address: `commxd --listen '[::]:4700' --advertise '[200:abcd::1]:4700'` (IPv6 addresses go in brackets). Mesh routes blink out for a few seconds when nodes move, so give rooms a longer grace window (`/room new camp --grace 60`) and keep them `host-only`, so a flapping member is removed instead of nuking the room. Each radio hop roughly halves throughput: text and files are fine, voice over more than two or three hops may stutter. Android can't join an ad hoc mesh without root; use a Linux laptop or a travel router as the mesh node. Turn on the mesh's own link encryption too (an 802.11s mesh with SAE/WPA3 under batman-adv, or Yggdrasil's built-in encryption). commx doesn't need it, but it keeps strangers off the mesh and hides more metadata.
- **LoRa radio, text only (experimental).** For when there's no network at all. Everyone joins over IP while together (a phone hotspot is enough), then the host types `/radio` and the room continues over [RNode](https://unsigned.io/rnode/) LoRa radios on USB. Details in [SPEC.md §18](SPEC.md#18-radio-profile-draft).
  - **Start:** `commxd --radio rnode:/dev/ttyACM0,freq=869525000,sf=9` on every node, with the same frequency and settings. There's no default frequency: use one that's licence-free where you are (e.g. 869.4–869.65 MHz in the EU). Never use amateur bands, which forbid encryption.
  - **What you get:** messages up to 134 bytes. Each one is sent once and heard directly by everyone in range; the host confirms the order, and lost packets are re-sent.
  - **Kill switch:** grace is 20 minutes by default (`--radio-grace`). Same kill modes as on IP; the host leaving still nukes the room.
  - **Airtime:** at SF9 with a 1% duty cycle (the default, and the limit on most EU 868 MHz sub-bands), about 25 messages per member per hour. `--radio-budget` sets the percentage to your band's limit; commxd never exceeds it.
  - **What's on the air:** every packet is one of four sizes, and the type, sender and counter are masked, so a listener can't tell a heartbeat from a short message. Keys ratchet every hour and old ones are erased: a radio seized later doesn't unlock what was recorded earlier. The IP room key is wiped at the handover for the same reason.
  - **Not hidden:** encryption hides what was said and who said it, not where you are. Radio transmitters can be located by direction-finding, and when you transmit shows when you're typing.
  - **Not yet:** voice, files, joining over the air, and Android (it can't reach USB radios yet). The RNode adapter hasn't been tested on hardware; `udp:127.0.0.1:4801,peer=127.0.0.1:4802,loss=0.2` simulates a radio between nodes on one machine.

## Kill switch

Each room chooses its kill mode when it's created. Every member enforces the host's choice.

| mode | host drops | a member drops |
|---|---|---|
| `host-only` (default) | room nuked everywhere | member removed, room key rotated |
| `any-member` (`--any-member`, all DMs) | room nuked everywhere | room nuked everywhere |

- **Disconnect:** a closed connection is a drop immediately.
- **Silence:** a silent peer (frozen, offline, asleep) counts as dropped after `--grace N` seconds (default 15).
- **Shutdown:** stopping `commxd` nukes its rooms and tells the peers.
- **What a nuke does:** it wipes the room key, the chain head, the sealed history and the file keys. It deletes the blob files, drops connections and takes the onion down.

**Sleep.** While any room is live, `commxd` keeps the machine awake: `caffeinate` on macOS, `systemd-inhibit` on Linux, `SetThreadExecutionState` on Windows. Closing a laptop lid still sleeps it. On wake, rooms past their grace window wipe themselves. For rooms that should survive your laptop, host them on an always-on box.

## Files

- **Announcement.** A file is announced through the room's signed hash chain. The announcement carries the name, size, BLAKE3 hash and a per-file key, all sealed under the room key.
- **Transfer.** Chunks travel on a separate bulk lane. Heartbeats always go first, so a big transfer can't trip the kill switch. The host relays chunks only from the person who announced the file.
- **On disk.**
  - Received files live in `<data-dir>/blobs/<random>.blob`.
  - Each blob is fixed-size encrypted slots, padded up to a size bucket with random bytes.
  - Blob names, sizes and contents say nothing about the file.
  - The file key exists only in RAM, so after a nuke (or a crash) a blob is noise. Blobs are unlinked on nuke, and orphans are purged at startup.
- **Export.** `/save` checks the hash and writes a decrypted copy. That copy is yours, and commx can't nuke it.

## Voice calls

`/call` starts a call in the current room, or joins the one already running. The voice stack doesn't use WebRTC, ICE or STUN, so there's nothing in it that can leak your IP. It's built on the same keys and connections as chat.

- **Signaling.** A call starts with a signed entry in the room's hash chain carrying a fresh call key, sealed under the room key. There's no signaling server to trust.
- **Encryption.** Audio is Opus at 24 kb/s. Every 20 ms frame is sealed with XChaCha20-Poly1305 under the call key, and has a replay window.
- **Group calls.** The host relays frames on a priority lane and doesn't mix them; each listener mixes locally.
- **What leaks: nothing about speech.**
  - The encoder runs in hard CBR and every frame is padded to the same size, so packet sizes can't leak words.
  - You send continuously while in a call, silence and mute included, so nobody can tell *when* you talk.
  - Cost: about 30 kb/s per participant.
- **Tor.** Calls work in Tor mode, with roughly walkie-talkie latency (0.5–1.5 s). The jitter buffer adapts and Opus conceals lost frames. Tor mode never opens a UDP socket.
- **Direct mode: UDP fast path.**
  - Voice goes over UDP on the same port as TCP. Each connection's UDP traffic is authenticated with keys derived from its Noise handshake, and the host only ever answers authenticated packets.
  - If UDP is blocked, calls fall back to TCP automatically. Pass `--no-udp` to disable UDP entirely.
  - The call header shows the active path: `udp`, `tcp` or `tor`.
  - If you host behind a router, forward UDP 4700 as well as TCP.
- **Microphone permission.** Audio runs in the `commx` TUI, so your OS asks for microphone permission for your terminal app. The daemon holds the keys.
- **Headphones.** Use them. There's no echo cancellation yet.
- **Testing alone.** `/echotest` runs your microphone through the whole receive path (Opus encode → jitter buffer → decode → mix → speakers) and plays you back about a second later. Use it to check devices and levels without anyone else.
- **Push-to-talk.** `/ptt`, then hold Space while the input box is empty.
  - Works in every terminal. Where the terminal reports key releases (Windows Terminal, kitty, WezTerm, Ghostty, foot, iTerm2 with CSI-u), the mic closes about 150 ms after you let go.
  - Elsewhere (e.g. macOS Terminal) the mic closes about 0.7 s after the key's auto-repeat stops.
  - Muting and push-to-talk still send silence frames, so they leak nothing.
- **Speaking indicator.** The call header highlights whoever is talking. Each listener works this out from the audio it decodes, so nothing extra is sent. The status bar shows your own mic level.
- **Devices.** `/devices` lists microphones and speakers; `/mic <n>` and `/speaker <n>` switch them, even mid-call. Device names never leave your machine.

## Reliability

**Design invariant: no single peer, room, file transfer, or UI operation can terminate the daemon.** `commxd` exits only on a shutdown signal or a startup failure.

| fault in | contained by | cost |
|---|---|---|
| a peer connection (garbage, hostile values, disconnects) | its own tasks, `Result` everywhere, overflow-checked counters | that connection |
| a room (any panic while handling it) | a fault boundary around every room operation, including each room's kill-switch tick | that room is nuked ("internal fault") and its peers are told |
| a file transfer | its own task; disk I/O runs off the async runtime | that transfer fails |
| a UI/IPC request | each request runs in its own task | an error reply; the client keeps working |
| core loops (peer listener, control socket, kill-switch ticker, UDP, tor) | a supervisor restarts them with backoff | a brief gap |

Release builds unwind on panic instead of aborting, so panics can be caught, and destructors still run and wipe keys. Panic messages are never printed (only their source location), so a crash log can't leak content. The fault-injection tests in `crates/commxd/tests/rooms.rs` do the following against real daemons:
- crash an IPC request;
- crash one room's message handling;
- crash one room's tick;
- crash the whole kill-switch ticker;
- spray garbage at the TCP and UDP ports.

Each time they check that everything else keeps working, including the kill switch.

## Memory hardening

The goal: a RAM dump or memory scan of commx shouldn't reveal messages.

- **Zero-on-free allocator** in both binaries. Every freed heap block is wiped, so plaintext doesn't linger.
- **Sealed history.** Chat history is kept *encrypted in RAM*, in both daemon and TUI. The TUI decrypts only the rows it's drawing.
- **Locked keys.** Keys live on locked pages: `mlock`/`VirtualLock`, `MADV_DONTDUMP`, wiped on free.
- **Sealed IPC.** The IPC event ring is sealed, and line buffers are wiped.
- **Process hardening.**
  - Core dumps are disabled everywhere.
  - Linux sets `PR_SET_DUMPABLE=0`.
  - macOS release builds refuse debugger attach.
  - Windows crash dumps (Windows Error Reporting) are disabled.

Verified: an lldb dump of a live host daemon after 10 canary messages contains **0** copies of them. The same scan of the pre-hardening build found plaintext.

Limits: text is plaintext while it's on screen. Your terminal emulator holds what it displays. Root or kernel-level access to a *running* process can still grab keys.

## Crypto

| piece | what |
|---|---|
| alias | Ed25519 + X25519. Each alias has its own keys, so aliases are unlinkable. |
| transport | Noise `XX_25519_ChaChaPoly_BLAKE2s` with a fresh node key per run. Aliases sign the handshake hash (channel binding). |
| room | XChaCha20-Poly1305 room key, sealed to each member and rotated on removal. |
| "blockchain" | Per-room hash chain, double-signed (author + host). Members reject gaps, reorders, forgeries and splices, and nuke the room if verification fails. It lives only in RAM. |
| password invites | Argon2id (19 MiB, t=2) of the password, salted with room and token. A keyed BLAKE3 proof bound to the Noise handshake hash, sent only after the host signs that same channel. |
| saved aliases | Argon2id (64 MiB, t=3) → XChaCha20-Poly1305, with authenticated parameters. Files have random names and sit in a private directory. |

See [SECURITY.md](SECURITY.md) for the audit and known limits, and [SPEC.md](SPEC.md) for the protocol itself (draft) and its open issues.

## Develop

Android: `rustup target add aarch64-linux-android x86_64-linux-android && cargo install cargo-ndk`, then `cd android && ./gradlew assembleRelease`. That builds the Rust core via `build-rust.sh`, then the APK. Release signing is set from the environment: `COMMX_KEYSTORE`, `COMMX_KEYSTORE_PASSWORD`, `COMMX_KEY_ALIAS` and `COMMX_KEY_PASSWORD`. In CI these come from the secrets `COMMX_KEYSTORE_B64` (a base64 keystore) plus the three passwords and alias.

```sh
cargo test --workspace                                 # unit + end-to-end (real daemons, SIGKILL/SIGSTOP)
cargo test -p commxd --test rooms -- --ignored tor     # live Tor test (needs tor + internet)
cargo clippy --target x86_64-pc-windows-gnu --workspace --all-targets -- -D warnings   # Windows check
```

```
crates/commx-core   identities, crypto, hash chain, secmem, local IPC, wire/IPC formats
crates/commxd       daemon: transports (TCP/Tor), rooms, kill switch, files, power, IPC server
crates/commx        ratatui TUI
crates/commx-voice  voice engine (Opus, jitter buffer, mixing, cpal), shared by TUI and Android
crates/commx-android  JNI bridge: embeds the daemon + voice engine in the Android app
android/            Android app (Kotlin, Jetpack Compose); build-rust.sh builds the .so files
dist/               launchd, systemd, Windows installer
```

## License

[AGPL-3.0-or-later](LICENSE). You can use, modify and share commx freely. If you distribute it, or run a modified version as a network service, you must publish your source under the same license.
