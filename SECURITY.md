# Security

commx is unaudited by third parties. This file records the internal review and the limits we know about.

## Threat model

**In scope:**
- **Network observers.** They can't see content. With Tor they can't see who talks to whom.
- **Non-member peers.** They can't join without an invite and can't read or inject anything.
- **A malicious member.** They can't forge others' messages, can't make the host accept undecryptable data, and can't flood the room.
- **A malicious host.** The host can't forge, reorder or drop messages without members detecting it and nuking the room.
- **Someone who later gets your disk.** Saved aliases are passphrase-encrypted. Blobs are ciphertext whose keys only ever lived in RAM.
- **Someone who dumps a running process's memory.** History is sealed in RAM and freed memory is wiped.

**Out of scope:**
- **A friend who decides to leak.** Nukes are cooperative; a modified client or a screenshot keeps anything.
- **Malware running as your user while commx is open.** It can drive the daemon over the local control channel or read the screen.
- **Root or kernel compromise.**
- **The host learning room metadata.** The host sees who is in the room and when people talk. It can read messages too, as a member.
- **Size-bucket leakage.** Blob padding hides exact file sizes, not the size bucket.

## Internal audit (October 2026)

Findings from reviewing the MVP, all fixed in commit `5a48646` unless noted. Regression tests live in `crates/commxd/tests/rooms.rs`.

| id | severity | finding | fix |
|---|---|---|---|
| H1 | high | Peer send queues were unbounded and members weren't rate-limited. One member could flood the host, which fanned every message out to all members, until it ran out of memory. | Bounded queues; a peer that can't keep up is dropped. Token bucket of 5 msg/s with a burst of 20 per member. |
| H2 | high | No cap on unauthenticated connections. Anyone who could reach the port could exhaust tasks and file descriptors. | At most 32 connections in the handshake/join phase; extras are shed. |
| M1 | medium | A custom `--socket` chmodded an existing parent directory and deleted any non-socket file at the socket path. | Only missing parents are created. Only stale *sockets* are removed. |
| M2 | medium | Remote room names, aliases and message text weren't sanitized. That allowed terminal escape injection (in `commx nuke` output) and bidi/zero-width spoofing. | Control and formatting characters are replaced at the daemon's trust boundary. Names are validated. |
| M3 | medium | Duplicate display names were allowed in a room, so one member could impersonate another. | The host rejects duplicate names, case-insensitively. Fingerprints are shown on join. |
| M4 | medium | Argon2 used library defaults (19 MiB, t=2), and the parameters weren't stored in the file, so they could never be raised. | Format `CXK2`: 64 MiB, t=3, with parameters stored in an authenticated header. |
| M5 | medium | Plaintext lingered in memory: history, IPC buffers and freed heap. | Fixed in `6e2c1a8`: sealed history, zero-on-free allocator, locked keys. Checked with a memory dump. |

## Internal audit #2 (October 2026, v0.1.0 → v0.2.0)

This covers everything since the first audit: memory hardening, Tor, files, Windows, voice, UDP and fault containment. **Both findings affect v0.2.0 and are fixed after it. Upgrade.**

| id | severity | finding | fix |
|---|---|---|---|
| H3 | high | **Path traversal on `/save`.** A malicious room member could announce a file named e.g. `../.ssh/authorized_keys` or `../Library/LaunchAgents/x.plist`. Receivers only stripped control characters, and `/save` joined the name onto Downloads, so the victim's daemon would create attacker-controlled files anywhere the user could write. That's persistence or code execution. | Received names are reduced to one safe path component at the trust boundary. Separators from every OS are handled; dot files, reserved names and over-long names are defused. `/save` independently refuses any path not directly inside the chosen directory, and opens with `O_NOFOLLOW`. An end-to-end test plays the malicious sender, and it fails on the old code. |
| M6 | medium | **DNS leak in Tor mode.** Joining a room always ran a system DNS lookup on the invite address, meant for the UDP fast path that Tor mode doesn't use. On Linux/glibc and Windows that sends a cleartext query for the room's `.onion` to the resolver. Observers could then see which IPs join the same room. | The lookup now runs only when the UDP path is on. `.onion` names are never handed to the system resolver in any mode. |

## Fault containment

A daemon crash is a denial of service against every room on that node, since the kill switch nukes them all. So the daemon treats "a peer can crash me" as a security bug:
- Peer-controlled counters are checked: chain sequence numbers and key epochs. A hostile host sending `next_seq = u64::MAX` used to overflow.
- Every peer/room/IPC boundary contains panics, and core loops are supervised. See [README → Reliability](README.md#reliability).
- Release builds switched from `panic = "abort"` to `"unwind"`. Under abort, any panic killed the daemon outright and skipped the destructors that wipe keys.

## Android

- **No control socket.** The daemon runs inside the app, and the UI talks to it over an in-process pipe, so no other app can find or connect to a control endpoint. Voice frames never enter the JVM.
- **Private storage, no backups.** Data lives in the app-private `filesDir`, and backups are disabled (`allowBackup=false` plus data-extraction rules that exclude everything).
- **Screen and notification.** `FLAG_SECURE` is set on the window. The notification is `VISIBILITY_SECRET` and carries no room names or content.
- **Limit: JVM strings can't be wiped.** Message text the UI displays lives in JVM strings until garbage collection. The Rust side (keys, sealed history, IPC buffers) keeps its memory hardening.
- **Limit: no Tor yet on Android.** Peers see your IP, as in desktop direct mode.
- **Limit: signing.** Builds without a release key are signed with a throwaway debug key. Only install APKs from the official release page.

## Web client

- **Who you trust is unchanged, mostly.** The page and its WebAssembly come from the room's host, which already sees the room as a member. There's no third-party server, and the browser still checks the host's identity key from the invite inside the Noise channel.
- **Limit: page code over plain http.** An active network attacker between browser and host can modify the code before it runs. That defeats everything the code does, including encryption. Use `--web-tls`, a trusted LAN/VPN, or the room's onion in Tor Browser, where the onion address authenticates the server.
- **`--web-tls` is only as good as the fingerprint check.** The certificate is self-signed, made fresh in RAM each run, and never written to disk. Browsers can't tell it from an attacker's self-signed certificate, so the friend has to compare the SHA-256 shown with the host's invite against the browser's certificate details before clicking through the warning. Plain http on a `--web-tls` port only redirects to https and never serves the client.
- **Hardened HTTP surface.**
  - Only a fixed list of files is served; no request path ever reaches the filesystem.
  - Strict CSP: no inline script, no remote origins, `connect-src` limited to the page's own origin (named explicitly for Safari).
  - `no-referrer`, `nosniff`, `frame-ancestors 'none'`, `no-store`.
  - WebSocket upgrades must be same-origin.
- **Untrusted text is never parsed as HTML.** It's only assigned via `textContent`.
- **Limit: browser memory can't be hardened.** JavaScript strings can't be wiped. On nuke, the page drops everything it displayed. Received files sit decrypted in WebAssembly memory, which is wiped when the room ends. A file you save becomes an ordinary download, and a decoded call's audio passes through the browser's audio stack.
- **Microphone.** Allowed only for the page's own origin (`Permissions-Policy: microphone=(self)`) and only while you're in a call. Muting sends silent frames, not nothing, so the host and network can't see when you talk.

## Known limits

- **Invites are bearer tokens.** `cx1:` invites are single use and last 10 minutes, but anyone who intercepts one first can join. Check the fingerprints shown on join.
- **Password invites (`cx2:`).** These are reusable until the room ends or is revoked, and need the code plus the password.
  - **Offline guessing:** the password-derived proof is bound to the Noise channel. It's only sent after the host proves its alias on that channel, so an interceptor learns nothing to guess against offline. The host itself holds the Argon2id key, as it would hold any password it sets.
  - **Online guessing:** limited to 5 wrong passwords per 10 minutes per invite, after which it pauses. A weak password can still fall to patient online guessing, so use a real passphrase. The flip side: someone who has the code but not the password can keep the invite paused. If that happens, make a new one (`/invite pw`).
  - **Who joined:** anyone with both can join any number of times, as a fresh alias each time. Watch the join lines and fingerprints, and revoke when done.
- **Late joiners miss running calls.** A member who joins while a call is already running doesn't get the call key, and can't join until a new call starts.
- **No reconnect.** A real disconnect is a drop, by design.
- **Voice frames aren't signed per sender.** They're authenticated as "someone holding the call key". A malicious participant, or the host, could inject audio attributed to someone else. Chat messages and files *are* signed. Per-frame signatures would roughly double call bandwidth.
- **UDP fast path (direct mode only).**
  - Each connection's UDP datagrams are encrypted and authenticated with a key derived from its Noise handshake hash.
  - Unauthenticated datagrams get no reply, and ping and pong are the same size, so the socket can't be used for amplification or aimed at third parties.
  - The host learns a member's UDP address only from that member's authenticated pings.
  - UDP is never used in Tor mode.
- **The host relays every call frame.** As a room member it can listen if it joins, and it sees who's in the call. Frame sizes and timing reveal nothing about speech.
- **Windows is compile-checked here and tested in CI,** but hasn't had hands-on testing yet.
- **Tor mode stores tor's consensus/guard cache** in `<data-dir>/tor`. That reveals commx used Tor, but nothing about rooms.
- **Exported files (`/save`) are plaintext** and outside commx's control.
