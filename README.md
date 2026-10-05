# commx

commx is peer-to-peer chat, voice calls and file sharing for small groups of friends. Everything is end-to-end encrypted. There are no servers, no accounts and no phone numbers, only aliases. Rooms self-destruct when nodes drop. It runs over Tor, or over direct TCP for a LAN or VPN.

```
 commx (TUI) ──private socket / pipe── commxd ──Noise_XX over TCP or Tor── other commxd nodes
```

- **`commxd`** is the node. It runs in the background, holds keys and rooms in locked memory, and talks to peers.
- **`commx`** is the terminal client. It talks only to your local `commxd`.

It runs on macOS, Linux and Windows. Android is planned.

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

## Use

```
/alias new ghost --ephemeral        RAM-only identity (drop --ephemeral to save it, passphrase-encrypted)
/room new lounge --any-member       host a room; prints a single-use invite (cx1:...)
/join cx1:...                       join a friend's room
/send ~/notes.pdf                   share a file (max 256 MiB)
/files   /save 1 [path]             list files / export a decrypted copy
/call    /hangup   /mute            start or join the room's voice call / leave / mute
/nuke    /nuke all                  destroy this room / everything
```

Send invite codes over a channel you trust. Each side shows a fingerprint for the other (`[abcd-efgh-...]`); compare fingerprints once, out of band. Panic button from any shell: `commx nuke`.

## Network

- **`--tor` (recommended).** `commxd` launches its own private tor process, which exits with it.
  - **Room addresses:** every room gets its own onion address. The keys are discarded at creation and the onion is deleted on nuke.
  - **Outgoing connections:** each one uses its own circuit.
  - **No IP leaks:** peers never see your IP. Clearnet addresses are refused, and the listener binds to loopback only.
  - **Timing:** first bootstrap takes about 15–30s. A new room's onion takes up to a minute before friends can join.
- **Direct TCP (default).** Port 4700. Use this on a LAN, or over Tailscale/WireGuard with `--advertise 100.x.y.z:4700`, or with a port forward. Peers see each other's IP.

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
| saved aliases | Argon2id (64 MiB, t=3) → XChaCha20-Poly1305, with authenticated parameters. Files have random names and sit in a private directory. |

See [SECURITY.md](SECURITY.md) for the audit and known limits.

## Develop

```sh
cargo test --workspace                                 # unit + end-to-end (real daemons, SIGKILL/SIGSTOP)
cargo test -p commxd --test rooms -- --ignored tor     # live Tor test (needs tor + internet)
cargo clippy --target x86_64-pc-windows-gnu --workspace --all-targets -- -D warnings   # Windows check
```

```
crates/commx-core   identities, crypto, hash chain, secmem, local IPC, wire/IPC formats
crates/commxd       daemon: transports (TCP/Tor), rooms, kill switch, files, power, IPC server
crates/commx        ratatui TUI
dist/               launchd, systemd, Windows installer
```

## License

[AGPL-3.0-or-later](LICENSE). You can use, modify and share commx freely. If you distribute it, or run a modified version as a network service, you must publish your source under the same license.
