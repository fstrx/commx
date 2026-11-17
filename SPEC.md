# commx protocol

**Status:** draft 0, describing commx v0.4.0 as built. Not frozen.

This document specifies the network protocol commx nodes speak to each other:
transport, joining, the room chain, keys, liveness and the kill switch, files
and calls. The local daemon ↔ client IPC is an implementation detail and is
out of scope.

The goal of writing it down is that someone could build a second, independent
implementation from this text alone. Until one exists, the Rust code in
`crates/commx-core` and `crates/commxd` is the tie-breaker wherever this
document is vague. Places where the current design is known to be weak are
called out inline and collected in [Open issues](#16-open-issues).

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Thesis

commx rooms are *presence-bound*: a room exists only while the people it
depends on are connected, and it is destroyed, not archived, when they leave.

1. **Liveness is a lifecycle rule.** Each room has a kill mode. In
   `HostOnly`, the room dies when the host drops. In `AnyMember`, it dies when
   anyone drops. Every node enforces the rule independently, from heartbeats.
2. **Transcript integrity without consensus.** One node (the host) sequences
   the room. Every entry is signed by its author and by the host and linked by
   hash, so the host can relay and order but not forge, edit, reorder or
   silently drop entries out of a member's view (see OPEN-1 and OPEN-2 for
   what it *can* still do).
3. **Nothing to recover.** Keys, chain and plaintext live only in memory. When
   a room ends, every node drops its keys; there is no history to subpoena,
   sync or restore.
4. **No accounts.** Identities are local key pairs ("aliases"). Admission is by
   invite: a capability handed over out of band.

Non-goals: offline delivery, multi-device sync, server-mediated discovery,
history for late joiners, and enforcing deletion on a modified client. The
kill switch is cooperative: an honest client wipes, a hostile one can keep
whatever it was shown.

## 2. Model

- **Alias.** A named identity: an Ed25519 signing key and an X25519 key
  agreement key, generated independently. Two aliases share no key material.
- **Node.** A running daemon. Each run generates a fresh Noise static key (the
  *node key*), never stored, so the transport layer can't link a node's
  aliases or sessions.
- **Room.** A random 16-byte `room_id`, a config, a member list, a room key,
  and a chain. Exactly one member is the **host**: the room's creator, who
  accepts connections, sequences the chain and relays traffic. Every other
  member holds exactly one connection: to the host. There is no host
  failover. A **DM** is a room with two members, kill mode `AnyMember`, and
  no reusable invite.

```
 member ──Noise──┐
 member ──Noise──┼── host (sequencer + relay)
 member ──Noise──┘
```

## 3. Primitives

| purpose | primitive |
|---|---|
| signatures | Ed25519, verified with `verify_strict` (RFC 8032, no malleable signatures) |
| key agreement | X25519 |
| AEAD | XChaCha20-Poly1305, 24-byte random nonces |
| hashing / KDF / MAC | BLAKE3 (`hash`, `derive_key`, `keyed_hash`) |
| transport | Noise `XX_25519_ChaChaPoly_BLAKE2s` |
| password hashing | Argon2id v0x13 |
| encoding | postcard 1.x (see §4) |
| text encoding | base32 (RFC 4648, no padding), lowercase |

All AEAD nonces are drawn from the OS RNG. With 192-bit nonces, random
nonces are safe for every key in this protocol.

## 4. Encoding

Every structure is serialized with [postcard 1.x](https://postcard.jamesmunns.com/wire-format)
in field declaration order:

- `u8`: one raw byte. `u16`, `u32`, `u64`: unsigned LEB128 varint.
- `bool`: one byte, `0` or `1`.
- `[u8; N]`: N raw bytes, no length.
- `Vec<T>`, `String`, `&str`: varint length, then the elements (UTF-8 for
  strings).
- Tuples and structs: fields concatenated, no tags.
- Enums: varint variant index (from 0, in declaration order), then the
  variant's fields.

Variant indices are part of the wire format. New variants MUST be appended,
never inserted or reordered.

> **OPEN-9.** postcard is well specified but uncommon outside Rust, and
> "declaration order" lives in Rust source. Before freezing, this document
> needs byte-level layouts for every message, plus test vectors.

Fixed-layout byte strings built outside postcard (AADs, signing contexts) are
written below with `||` for concatenation, `BE32`/`BE64` for big-endian
integers and `LE16` for little-endian.

## 5. Identities

```
PublicIdentity { sign_pk: [u8; 32], dh_pk: [u8; 32] }
MemberInfo     { name: String, id: PublicIdentity }
```

**Fingerprint** (shown to humans for out-of-band checks):

```
fp = BLAKE3("commx-fp-v1" || sign_pk || dh_pk)[0..10]
display = base32_lower(fp) split into groups of 4 joined by "-"
```

80 bits: enough against second preimages, which is what matters (an attacker
must match a key someone else already has).

**Names** are display-only. An alias name MUST be 1–32 bytes, contain no
whitespace or control characters and have no leading or trailing spaces. A
room name MUST be 1–48 bytes under the same rules, except that it may contain
spaces. A host MUST refuse a joiner whose name equals an existing member's,
case-insensitively. Receivers MUST neutralize control and formatting characters (including
bidi overrides) in every displayed string a peer supplied.

## 6. Invites

```
Invite { addr: String, host: PublicIdentity, room_id: [u8; 16], token: [u8; 16] }
code = prefix || base32_lower(postcard(Invite))
```

- `addr` is `host:port`: a direct address, or `<onion>.onion:4700` for Tor.
- `host` pins the host's alias keys. A joiner MUST abort if the host proves
  any other identity.
- The body is decoded case-insensitively. Whitespace around the code is
  ignored.

| prefix | kind | rules |
|---|---|---|
| `cx1:` | single-use | The host accepts `token` once, within 10 minutes of issuing it. |
| `cx2:` | password | Reusable until the room ends or the host revokes or replaces it. Useless without the password (§9.2). The body has the same format as `cx1:`. |

A host keeps at most one `cx2:` invite per room. Issuing a new one revokes
the old one. DMs MUST NOT have a `cx2:` invite.

**Web link.** A host serving the browser client (§7.3) MAY also publish
`http(s)://<addr>/#<code>`. The code rides in the URL fragment, which browsers
never send to the server.

## 7. Transport

### 7.1 Framing and Noise

A connection is a reliable byte stream (TCP, a Tor stream, or a WebSocket,
§7.3). On it, every message is

```
frame = BE32(len) || bytes      ; len ≤ 65535
```

The dialer is the Noise initiator. The handshake is `XX` with empty payloads
and no prologue (OPEN-8), using each side's node key as static key:

```
-> e
<- e, ee, s, es
-> s, se
```

After the handshake, each frame carries one Noise transport message. Its
plaintext is `postcard(WireMsg)` (§8). The Noise nonce counts frames in each
direction from 0. A plaintext MUST NOT exceed 65519 bytes (65535 minus the
16-byte tag).

The node keys authenticate nothing about who is behind them. Identity comes
from **channel binding**: aliases sign the handshake hash `h`.

```
channel_binding(h, role) = "commx-chan-v1:" || role || ":" || h
role ∈ { "member", "host", "invite-password" }
```

A signature or proof over `channel_binding(h, …)` is valid only on the
channel with handshake hash `h`. It can't be relayed to another connection,
which defeats a man in the middle with their own node key.

Connections time out if the handshake hasn't completed within 10 s (60 s over
Tor). A dialer gives up if the first reply hasn't arrived within 10 s.

### 7.2 Tor

In Tor mode, a host publishes one fresh v3 onion service per room (virtual
port 4700) and removes it when the room ends. A node in Tor mode MUST refuse
to dial non-onion addresses, MUST NOT resolve onion names through the system
resolver, and MUST NOT open the UDP path (§13.4).

### 7.3 Browser members

A host MAY serve a browser client on its peer port. It tells the protocols
apart by peeking at the first bytes of a connection:

| first bytes | meaning |
|---|---|
| `GET ` | HTTP: static client files, or a WebSocket upgrade at `/ws` |
| `0x16` | TLS ClientHello (only with `--web-tls`; plain HTTP then gets a 308 to https) |
| anything else | a native peer starting Noise |

On `/ws`, binary WebSocket messages carry the raw byte stream of §7.1:
frames may be split or merged across messages, and message boundaries carry
no meaning. Above the byte stream, a browser is an ordinary member.

The browser client is served from the host. Its integrity therefore rests on
TLS to that host: plain HTTP is only safe on a trusted LAN. With
`--web-tls`, the certificate is self-signed per run and its SHA-256
fingerprint is shown next to the invite, to be compared out of band.

## 8. Wire messages

`WireMsg`, by variant index:

| # | variant | direction | fields |
|---|---|---|---|
| 0 | `JoinReq` | M→H | `room_id`, `token: [16]`, `member: MemberInfo`, `sig` |
| 1 | `JoinOk` | H→M | `cfg: RoomConfig`, `host: MemberInfo`, `host_sig`, `epoch: u32`, `sealed_key: Sealed`, `members: Vec<MemberInfo>`, `next_seq: u64`, `head: [32]` |
| 2 | `JoinDenied` | H→M | `reason: String` |
| 3 | `Submit` | M→H | `Payload` (§10.1) |
| 4 | `Block` | H→M | `Block` (§10.1) |
| 5 | `Heartbeat` | both | (none) |
| 6 | `FileChunk` | both | `room_id`, `file_id: [16]`, `idx: u32`, `nonce: [24]`, `ct` |
| 7 | `CallPresence` | both | `room_id`, `call_id: [16]`, `member: [32]` (sign_pk), `joined: bool` |
| 8 | `Voice` | both | `room_id`, `call_id: [16]`, `from: [32]`, `seq: u64`, `nonce: [24]`, `ct` |
| 9 | `Nuke` | H→M | `room_id`, `sig` |
| 10 | `Leave` | M→H | `room_id` |
| 11 | `JoinHello` | M→H | `room_id`, `token: [16]` |
| 12 | `HostProof` | H→M | `host: MemberInfo`, `sig` |
| 13 | `JoinReqPw` | M→H | `room_id`, `token: [16]`, `member: MemberInfo`, `sig`, `proof: [32]` |
| 14 | `RadioGo` | H→M | `room_id`, `head: [32]`, `grace_secs: u64`, `sig` (§18.2) |

Signatures (`sig`, `host_sig`) are `Vec<u8>` holding 64 bytes. A node MUST
ignore messages that make no sense for the peer's role (for example a
`Block` from a member).

A connection carries one room. To be in several rooms, a node opens one
connection per room.

```
RoomConfig { name: String, kill_mode: KillMode, grace_secs: u64, is_dm: bool }
KillMode   = HostOnly (0) | AnyMember (1)
Sealed     { eph_pk: [32], nonce: [24], ct: Vec<u8> }
```

## 9. Joining

### 9.1 Single-use invite (`cx1:`)

```
M: dial addr, Noise XX → h
M → H  JoinReq { room_id, token, member, sig = Sign_M(channel_binding(h, "member")) }
H:     check token (unused, unexpired, this room); consume it
H:     verify sig with member.id.sign_pk; check name rules; DM not full; not already a member
H:     sequence Block(Body::Join { member })   (seen by existing members)
H → M  JoinOk { cfg, host, host_sig = Sign_H(channel_binding(h, "host")),
                epoch, sealed_key = seal_to(member.dh_pk, room_key[epoch]),
                members, next_seq, head }
M:     require host.id == invite.host and host_sig valid; else abort
M:     open sealed_key; resume chain at (next_seq, head)
```

The host consumes the token before the other checks, so a failed attempt
burns it. On any failure the host sends `JoinDenied { reason }` and closes.
Joiners MUST sanitize `reason` before showing it.

The joiner never sees the room's earlier blocks, and `next_seq` already
accounts for its own `Join` block.

> **OPEN-3.** `cfg`, `members` and `head` in `JoinOk` are trusted because the
> channel is bound to the host. They are not committed to anything other
> members can check, so a hostile host can tell different members different
> kill modes, grace periods or member lists. See §16.

### 9.2 Password invite (`cx2:`)

The password must never be exposed to anyone but the real host, including
something derived from it that would allow offline guessing. The joiner
therefore makes the host prove its identity first.

```
key   = Argon2id(password, salt = "commx-invite-v1:" || room_id || token,
                 m = 19456 KiB, t = 2, p = 1, out = 32 bytes)
proof = BLAKE3_keyed(key, channel_binding(h, "invite-password"))
```

```
M: derive key (before dialing); dial, Noise XX → h
M → H  JoinHello { room_id, token }
H:     token must be the room's current cx2 token, and the invite not paused
H → M  HostProof { host, sig = Sign_H(channel_binding(h, "host")) }
M:     require host.id == invite.host and sig valid; else abort WITHOUT sending proof
M → H  JoinReqPw { room_id, token, member, sig = Sign_M(channel_binding(h, "member")), proof }
H:     constant-time compare proof; on mismatch record a failure, deny "wrong password"
H:     then as §9.1 from "verify sig"
```

- The host stores only `key` (it's never told the password itself), and drops
  it when the room ends or the invite is replaced or revoked.
- A proof is bound to `h`, so a captured proof is worthless on any other
  connection. A man in the middle never gets a proof, because they can't
  produce `HostProof`.
- **Online guessing** is limited: after 5 wrong proofs within 10 minutes, the
  host pauses the invite (answering `JoinHello` with `JoinDenied`) until the
  oldest failure ages out. The host's own user is shown every failure.
- The cost is low (19 MiB) because browsers must compute it, and offline
  guessing requires being the host, who knows the password anyway.

> Anyone holding the code but not the password can keep the invite paused
> forever. The remedy is a new `cx2:` invite (new token).

## 10. The room chain

### 10.1 Payloads and blocks

```
Payload { room_id: [16], author: [32] (sign_pk), epoch: u32, ts_min: u64, body: Body, author_sig: Vec<u8> }
Block   { seq: u64, prev_hash: [32], payload: Payload, host_sig: Vec<u8> }

author_sig = Sign_author(postcard(("commx-payload-v1", room_id, author, epoch, ts_min, body)))
host_sig   = Sign_host(postcard(("commx-block-v1", seq, prev_hash, payload)))   ; payload incl. author_sig
block_hash = BLAKE3(postcard(Block))
```

`ts_min` is Unix time in whole minutes, coarsened to leak less timing. It is
chosen by the author and is not checked.

The chain starts with `seq = 0` and `prev_hash = 0^32`. There is no genesis
block (OPEN-3). Each block's `prev_hash` is the previous block's
`block_hash`.

**Member verification.** A member holds only `(next_seq, head)`. For each
`Block` it MUST check, in this order:

1. `payload.room_id` is this room,
2. `seq == next_seq` (no gaps, replays or reorders),
3. `prev_hash == head`,
4. `host_sig` verifies under the host's `sign_pk` from the invite,
5. `author_sig` verifies under `payload.author`,

then set `head = block_hash`, `next_seq += 1`, and interpret the body
(§10.2). A failure at any step, or while interpreting the body, means the
host is misbehaving: the member MUST nuke the room (§12.3). Blocks are not
retained after they've been applied.

> **OPEN-2.** Verification is per member. Nothing stops a host from showing
> different members different blocks at the same `seq` (equivocation). Each
> view is internally consistent, and members never compare heads.

### 10.2 Bodies

`Body`, by variant index:

| # | variant | author | meaning |
|---|---|---|---|
| 0 | `Msg { nonce: [24], ct }` | any member | chat message |
| 1 | `KeyRotate { new_epoch: u32, sealed: Vec<([32], Sealed)> }` | host only | new room key, sealed per remaining member (§11) |
| 2 | `Join { member: MemberInfo }` | host only | member added |
| 3 | `File { file_id: [16], nonce: [24], ct }` | any member | file announcement (§13.1) |
| 4 | `Call { call_id: [16], nonce: [24], ct }` | any member | call start (§13.2) |
| 5 | `Leave { sign_pk: [32] }` | host only | member removed |

A `Msg`, `File` or `Call` whose author isn't a current member, or a
host-only body from anyone else, is an integrity failure.

**Message content.**

```
plaintext = postcard(ChatPlain { text: String })   ; text ≤ 8 KiB
aad       = room_id || BE32(epoch) || author
ct        = XChaCha20-Poly1305(room_key[epoch], nonce, plaintext, aad)
```

### 10.3 Host acceptance

A member sends `Submit(payload)`. The host MUST sequence it only if
`room_id` matches, `author` is the alias authenticated on that connection,
`author_sig` is valid, the body is `Msg`, `File` or `Call`, and it decrypts
under the stated epoch (and, for `File`, `file_id` is new). Otherwise the
host drops it silently. Checking decryption keeps one broken member from
tripping every other member's integrity check.

The host rate-limits submissions per member (token bucket: 5/s, burst 20).
It authors `Join`, `Leave` and `KeyRotate` itself, and its own messages go
straight into the chain.

> **OPEN-1.** A host can also drop *valid* submissions, and the author is
> never told. Nothing acknowledges a `Submit`.

## 11. Room keys

The room key is 32 random bytes, numbered by `epoch` (starting at 0).

**Sealed box** (anonymous encryption to an X25519 key):

```
e        = fresh X25519 key pair
shared   = X25519(e.sk, recipient_dh_pk)
k        = BLAKE3_derive_key("commx seal v1", shared || e.pk || recipient_dh_pk)
Sealed   = { eph_pk: e.pk, nonce, ct = XChaCha20-Poly1305(k, nonce, plaintext, aad = "commx-sealed") }
```

**Rotation.** When the host removes a member in a `HostOnly` room, it
appends `Leave { sign_pk }`, then `KeyRotate { new_epoch = epoch + 1,
sealed }`, with the new key sealed to every remaining member except itself.
A member MUST find its own entry or treat the block as an integrity failure.
Nodes keep the current epoch's key and the one before it (for messages in
flight) and wipe older ones.

> **OPEN-5.** Keys change only on removal. Within an epoch there is no
> forward secrecy: one key decrypts every message since the last removal.
>
> **OPEN-6.** The sealed box's AAD is a constant. It isn't bound to the room,
> epoch or purpose.

## 12. Liveness and the kill switch

### 12.1 Heartbeats

Every node sends `Heartbeat` on each room connection every
`clamp(grace_secs / 3, 1, 5)` seconds. Any received message counts as
proof of life. A peer is **down** when nothing has arrived from it for more
than `grace_secs` (default 15, minimum 2), when its connection closes, or
when its outgoing queue overflows (it can't keep up).

A node that detects a gap in its own wall clock (system sleep) longer than
`grace_secs` MUST treat all its rooms as already dead and nuke them locally.
Its peers will have done the same.

### 12.2 Policy

| event | `HostOnly` | `AnyMember` |
|---|---|---|
| host down (seen by a member) | member nukes locally | member nukes locally |
| member down (seen by the host) | host appends `Leave`, rotates the key | host broadcasts `Nuke` and nukes |
| member sends `Leave` | same as member down | same as member down |
| block fails verification | member nukes locally | member nukes locally |
| host user ends the room | `Nuke` to all | `Nuke` to all |
| member user leaves | sends `Leave`, wipes locally | sends `Leave`, wipes locally |

### 12.3 Nuke

```
Nuke { room_id, sig = Sign_host("commx-nuke-v1:" || room_id) }
```

A member MUST accept a `Nuke` only from its host connection, only for that
room, and only with a valid signature. To nuke, a node wipes every key (room,
file, call), chain state, plaintext and invite for the room, deletes its
temporary file blobs, and closes the room's connections. A room id is never
reused, so a nuke signature can't be replayed against anything else.

## 13. Files and calls

### 13.1 Files

The sender picks a random `file_id` and a random 32-byte file key, then
announces:

```
FileMeta  { name: String, size: u64, chunks: u32, hash: [32], key: [32] }
chunks    = max(1, ceil(size / 32768)) ; size ≤ 256 MiB
hash      = BLAKE3(entire plaintext)
File.ct   = XChaCha20-Poly1305(room_key[epoch], nonce, postcard(FileMeta),
                               aad = room_id || BE32(epoch) || author || "file" || file_id)
```

After that, the sender streams the file as chunks:

```
FileChunk.ct = XChaCha20-Poly1305(file_key, nonce, plaintext[idx*32768 .. +32768],
                                  aad = "commx-chunk" || file_id || BE32(idx))
```

- Chunks are not part of the chain. They are authenticated by the AEAD
  (which binds file and position) and finally by the signed `hash`.
- Nodes drop chunks for unknown files. A sender therefore MUST NOT send a
  file's chunks until its announcement is sequenced, or at least ordered
  ahead of them on the same connection.
- Only the announcer may supply a file's chunks. The host relays a member's
  chunks to every other member.
- A receiver checks each chunk's size, assembles them, and accepts the file
  only if its BLAKE3 hash matches. It fails the file on a bad chunk, a hash
  mismatch, or 90 s without progress.
- Receivers treat `name` as untrusted and sanitize it before using it as a
  path.

### 13.2 Calls

A call starts with a chain entry carrying a fresh call key:

```
CallMeta  = { key: [32] }
Call.ct   = XChaCha20-Poly1305(room_key[epoch], nonce, postcard(CallMeta),
                               aad = room_id || BE32(epoch) || author || "call" || call_id)
```

A sequenced `Call` block replaces any running call. Its author is the first
participant.

**Roster.** A member sends `CallPresence { call_id, member = its own
sign_pk, joined }`. The host accepts presence only about the sender itself,
updates the roster, and rebroadcasts the change. Members take roster updates
only from the host. The host removes participants whose connection drops.
The call ends when its roster is empty.

> **OPEN-7.** Someone who joins the room while a call is running never learns
> its key (it's in a block from before they joined). They can't take part
> until a new call starts.

### 13.3 Voice frames

Audio is Opus, 48 kHz mono, 20 ms frames, hard CBR at 24 kb/s (60-byte
packets).

```
plain = LE16(len) || opus || zero padding       ; exactly 128 bytes
aad   = "commx-voice" || room_id || call_id || from || BE64(seq)
Voice.ct = XChaCha20-Poly1305(call_key, nonce, plain, aad)
```

- Participants send a frame every 20 ms for as long as they're in the call,
  silence and mute included. Frame size and timing reveal nothing about
  speech.
- `seq` starts at 1 per sender per call and increases by one per frame.
  Receivers keep a 64-frame sliding replay window per sender.
- The host forwards a frame only if the sender is in the roster, `from`
  equals the sending connection's alias, the frame decrypts, and it isn't a
  replay. It also caps each sender at 60 frames/s. It relays only to other
  participants.
- Voice is never queued behind other traffic: when the media lane is full,
  frames are dropped.

> **OPEN-4.** A frame proves only "sent by someone holding the call key".
> Between participants, `from` is trusted, so a hostile participant or host
> can inject audio in someone else's name.

### 13.4 UDP fast path (optional)

In direct (non-Tor) mode, each room connection also gets a UDP path to the
host's TCP port, keyed from the handshake hash:

```
udp_key = BLAKE3_derive_key("commx udp key v1", h)
path_id = BLAKE3_derive_key("commx udp id v1", h)[0..8]
datagram = path_id || nonce(24) || XChaCha20-Poly1305(udp_key, nonce, postcard(UdpMsg), aad = path_id)
UdpMsg = Ping (0) | Pong (1) | Voice(WireMsg::Voice) (2)        ; datagram ≤ 1200 bytes
```

- The member pings every second. The host learns the member's address only
  from authenticated pings and answers with a pong.
- A path is used for voice while something was received on it within the
  last 3 s. Otherwise voice falls back to the connection's media lane.
- This layer only authenticates the hop: voice inside is still sealed with
  the call key.

## 14. Limits

| item | limit |
|---|---|
| frame | 65535 bytes (plaintext 65519) |
| chat text | 8 KiB |
| file | 256 MiB, 32 KiB chunks |
| `cx1:` invite lifetime | 10 min, single use |
| password failures | 5 per 10 min, then the invite pauses |
| submissions per member | 5/s, burst 20 |
| voice frames per sender | 60/s |
| grace window | ≥ 2 s, default 15 s |
| alias / room name | 32 / 48 bytes |

## 15. Security properties

Assuming honest endpoints and sound primitives, the protocol is designed for
the following:

- **Confidentiality** of messages, files, call audio and room metadata (names,
  config, members) against the network, including Tor relays and anyone
  relaying the WebSocket.
- **Host authentication**: a joiner talks to the alias pinned in its invite,
  or aborts.
- **Member authentication**: the host knows which alias is on each
  connection, and every entry is signed by its author.
- **No forgery or tampering by the host**: it can't fabricate, alter, reorder
  or splice entries in a member's view without that member detecting it and
  nuking.
- **Removal**: after `Leave` + `KeyRotate`, a removed member can't decrypt
  new entries.
- **Password secrecy** for `cx2:` invites against everyone but the host.
- **Unlinkability**: separate aliases share no keys, and node keys change
  every run. Tor mode adds network-level unlinkability.
- **No persistent state**: nothing about a room is ever written to storage,
  except temporary encrypted file blobs whose keys are in memory only.

What the protocol does **not** provide:

- **Metadata privacy from the host.** It sees who is in the room, who sends
  what and when, sizes, and who is in a call.
- **Censorship resistance against the host.** It can drop submissions
  (OPEN-1) and equivocate (OPEN-2).
- **Deletion by a modified client.** The kill switch is cooperative.
- **Availability.** The kill switch is a denial of service by design: in
  `AnyMember`, anyone can end the room by disconnecting.

## 16. Open issues

Items to settle before calling the protocol 1.0. Fixes are proposals, not
decisions.

| id | issue | proposed fix |
|---|---|---|
| OPEN-1 | **Silent drops.** A host can discard valid submissions, and the author never knows. | Authors watch for their own payload (by hash) coming back in a block and warn after a timeout. Optionally the host returns a signed receipt. |
| OPEN-2 | **Equivocation.** The host can send different blocks at the same `seq` to different members. | Add `seen: (seq, head)` to `Payload`, covered by `author_sig`. Every member checks other members' `seen` against its own history of heads (kept as a short window of hashes), and nukes on a mismatch. The host can then only hide a fork from members who never speak. |
| OPEN-3 | **Room config and snapshot not committed.** `cfg`, `members`, `next_seq` and `head` in `JoinOk` are taken on the host's word. The kill mode, the core of the thesis, is not signed into anything other members can compare. | Add a genesis block (`Body::Genesis { cfg }`, seq 0) and send the joiner a host-signed `(room_id, cfg_hash, next_seq, head, members)` snapshot. Members can then compare `cfg_hash` (and with OPEN-2, heads). |
| OPEN-4 | **Voice frames aren't sender-authenticated.** | Per-sender keys: each participant derives `BLAKE3_derive_key("commx voice sender v1", call_key || sign_pk)`. That stops honest participants being confused but not a hostile one, who still holds every key. Full fix: per-frame signatures (doubles bandwidth) or a per-sender key announced in a signed chain entry, plus a MAC chain. |
| OPEN-5 | **No forward secrecy within an epoch.** | A hash ratchet: `room_key[e, n+1] = BLAKE3_derive_key("commx ratchet v1", room_key[e, n])`, stepped every N blocks or M minutes, with the step index in `Payload`. Longer term, MLS (RFC 9420) for group keys, which also gives post-compromise security. |
| OPEN-6 | **Sealed boxes aren't bound to context.** | AAD = `"commx-sealed-v2" || room_id || BE32(epoch) || purpose`. |
| OPEN-7 | **Late joiners miss running calls.** | When a member joins mid-call, the host (or the call's starter) seals `CallMeta` to the joiner in a `CallSync` message. |
| OPEN-8 | **No versioning.** Nothing in the handshake says which protocol version either side speaks. | Noise prologue `"commx/<major>"` (a mismatch fails the handshake cleanly), plus a `Hello { version, features }` as the first transport message. Invite prefixes already carry a format version. |
| OPEN-9 | **Rust-shaped encoding.** | Byte-level layouts in this document plus test vectors (§17). Consider a tagged, length-delimited format if a second implementation finds postcard painful. |
| OPEN-10 | **No formal analysis.** | Model the join (§9.1 and §9.2) and chain rules in Tamarin or ProVerif: host authentication, proof secrecy against a MITM, injective agreement on blocks. |
| OPEN-11 | **Host-chosen timestamps.** `ts_min` is author-chosen and unchecked. | Members flag entries more than a few minutes off their own clock. |
| OPEN-12 | **Uploads stall** when the host refuses an announcement: the sender never learns. | Fixed by OPEN-1 (the sender sees its announcement never comes back). |

## 17. Road to 1.0

1. Resolve or explicitly accept each open issue. Bump the major version for
   any change to the wire.
2. Test vectors generated from `commx-core`: fixed keys, nonces and inputs,
   with expected bytes for invites, channel bindings, payload and block
   signing bytes, block hashes, sealed boxes, password proofs, voice frames
   and UDP datagrams.
3. A second implementation in another language (TypeScript or Go) that joins
   a commx room and chats, built only from this document. The browser client
   doesn't count: it reuses the Rust core.
4. The formal model of OPEN-10.
5. An external review.

## 18. Radio profile (draft)

A text-only variant for LoRa and similar links: a few kb/s at best, packets
of about 230 bytes, broadcast, lossy, and limited by law to a small share of
airtime. Nothing in §7–§13 fits that. A single "hi" costs about 280 bytes
there, every message crosses the air twice, and heartbeats every 5 s would
blow the airtime budget many times over. This profile keeps the thesis
(presence-bound rooms, signed authorship, a host-sequenced chain, nothing
persisted) and gives up everything but text.

A prototype lives in `crates/commx-radio` (a sans-IO state machine plus
link adapters) and is wired into `commxd` behind `--radio`. Its simulation
tests run the profile at 20% packet loss, with hidden nodes, missed re-keys,
replayed packets and an equivocating host.

### 18.1 Constraints

Approximate LoRa airtime (125 kHz bandwidth, coding rate 4/5, explicit
header, CRC on, 8-symbol preamble):

| spreading factor | 40-byte packet | 230-byte packet | full packets/hour at 1% duty cycle |
|---|---|---|---|
| SF7 | 0.08 s | 0.36 s | ~100 |
| SF9 | 0.29 s | 1.15 s | ~30 |
| SF12 | 2.0 s | 8.2 s | ~4 |

- **Spreading factor.** SF7–SF9 is the practical range for chat. SF12 reaches
  further but carries about four messages an hour.
- **Duty cycle.** The 1% limit is the EU 868 MHz rule. Other regions limit
  airtime differently (for example, dwell time per transmission), so
  implementations MUST let the operator set an airtime budget and MUST stay
  under it.
- **No amateur bands.** Encryption is not allowed there. This profile is
  only for licence-free ISM bands.
- **Location.** Radio transmissions can be direction-found. Encryption hides
  what is said and who said it, not where the transmitter is. Tor-style
  anonymity is impossible on radio.

### 18.2 Model

- **Joining stays on IP.** Members join with the normal §9 handshake over any
  IP link: the host's Wi-Fi hotspot, a LAN, or a mesh, usually while the group
  is together. Joining over the air is out of scope for now, and so is
  joining a room that is already on radio.
- **Handover.** The host sends every member
  `RadioGo { room_id, head, grace_secs, sig }` over IP, where `head` is its
  IP chain head and `sig` signs
  `"commx-radio-go-v1:" || room_id || head || BE64(grace_secs)`. It then
  drops its IP peers. A member that verifies the signature MUST check `head`
  against its own chain head and nuke on mismatch, or nuke if it has no
  radio. Otherwise it switches over. From then on IP connections are ignored
  and losing them is not a drop. The radio chain starts from
  `head_0 = BLAKE3("commx-radio-start-v1" || room_id || head)`. Calls and
  files end at the handover.
- **Broadcast.** Every packet is one broadcast transmission. The author sends
  a message once, and everyone in range hears it directly. The host does not
  repeat messages. Instead it periodically broadcasts a small signed `ORDER`
  packet that sequences what it heard.
- **Member index.** Each member has a 1-byte index: its position in the
  room's member list at handover (host = 0, then join order, as built from
  `JoinOk.members` plus later `Join` and `Leave` blocks, so every member
  derives the same table). At most 255 members. This replaces 32-byte keys
  on the air.
- **Pairwise keys.** Each member shares a key with the host:
  `pair_key = BLAKE3_derive_key("commx radio pair v1", X25519(member, host) || room_id)`.
  It authenticates cheap control packets (beats, repair requests) that only
  the host needs to check, and carries the new room key during re-keying.

### 18.3 Packet format

```
radio_key[e] = BLAKE3_derive_key("commx radio key v1", room_key[e])
hp_key[e]    = BLAKE3_derive_key("commx radio hp v1",  room_key[e])
tag          = BLAKE3_keyed(radio_key[e], "tag" || BE32(unix_hour))[0..4]

packet = tag(4) || header(12) XOR mask || AEAD(radio_key[e], nonce, body, aad = tag || header)
header = type(1) || sender(1) || ctr(BE24) || epoch(1, low byte) || seen_seq(BE16) || seen_head(4)
nonce  = BLAKE3_derive_key("commx radio nonce v1", BE32(epoch) || sender || ctr)[0..24]
mask   = BLAKE3_keyed(hp_key[e], ciphertext[0..16])[0..12]
```

- **Fixed overhead:** 32 bytes per packet (4 tag + 12 header + 16 AEAD tag).
- **Tag.** Lets a receiver drop other rooms' traffic cheaply, and rotates
  hourly so the room isn't trivially linkable over time. Receivers try the
  current, previous and next hour.
- **Header protection.** The header is masked as in QUIC (RFC 9001 §5.4), so
  outsiders see neither the packet type nor the sender, counter or sizes of
  fields. A receiver unmasks the header using the first 16 ciphertext bytes,
  then derives the nonce and opens the body.
- **Counters.** `ctr` counts every packet a sender transmits, of any type,
  per epoch. It MUST never repeat, which makes the derived nonce unique.
  Receivers keep a 64-entry replay window per sender, and
  `(sender, epoch, ctr)` identifies a packet everywhere (for ordering and
  repair).
- **Seen fields.** `seen_seq` and `seen_head` are the sender's latest
  `ORDER` sequence number and the first 4 bytes of its chain head (§18.5).
  Every packet thereby reports the sender's view of the chain, which is what
  detects a host showing different members different chains (OPEN-2).

### 18.4 Packet types

| type | from | body | authenticated by |
|---|---|---|---|
| `MSG` (0) | any member | `text || sig(64)` | author signature |
| `ORDER` (1) | host | `first_seq(BE24) || n(1) || n × (sender(1) || epoch(1) || ctr(BE24) || hash(8)) || sig(64)` | host signature |
| `BEAT` (2) | any member | `mac(8)` | pairwise key (host checks; host's own beats are `ORDER`s) |
| `REPAIR` (3) | any member | `n(1) || n × (sender(1) || epoch(1) || ctr(BE24)) || mac(8)` | pairwise key |
| `JOIN` (4) | host | reserved for over-the-air joins (§18.8); ignored | — |
| `REMOVE` (5) | host | `index(1) || sig(64)` | host signature |
| `REKEY` (6) | host | `new_epoch(1) || n × (index(1) || AEAD(pair_key, new_key) (48)) || sig(64)`, sealed under the *previous* epoch | host signature |
| `NUKE` (7) | host | `sig(64)` | host signature |

Signatures go inside the encrypted body, so an outsider who knows a member's
public key can't test packets against it. Each type signs its own context:
`"commx-radio-<type>-v1" || room_id || header || body-without-sig`. For
example, `MSG` signs `"commx-radio-msg-v1" || room_id || header || text`.

**Text.** With a 230-byte radio MTU, a `MSG` carries up to 134 bytes of
UTF-8 text (230 − 32 − 64). Longer messages are refused; there's no
fragmentation. Senders pad text with zero bytes to a multiple of 16 (at most
134), so packet sizes reveal less about content; receivers strip trailing
zeros.

**Sizes.** An `ORDER` entry is 13 bytes, so one `ORDER` sequences up to 10
messages (32 + 4 + 130 + 64 = 230). A `REPAIR` asks for up to 37 packets.
A `REKEY` carries 2 members (32 + 1 + 98 + 64 = 195); 3 would not fit.
Entry `epoch` bytes are the low byte of the epoch, resolved against the
two epochs a node holds.

**Re-key AEAD.** XChaCha20-Poly1305 under `pair_key`, with
`nonce = BLAKE3_derive_key("commx radio rekey nonce v1", BE32(new_epoch) || index)[0..24]`
and `aad = room_id || BE32(new_epoch) || index`. The nonce repeats only when
the same key is resent to the same member, with the same plaintext.

`hash` in an `ORDER` entry is `BLAKE3(packet)[0..8]` of the referenced packet
as received. `MAC`s are `BLAKE3_keyed(pair_key, header || body-without-mac)[0..8]`.

### 18.5 Ordering and the chain

- **Show on arrival.** Members display a `MSG` as soon as it decrypts and its
  signature verifies, marked "unconfirmed".
- **Order in batches.** The host broadcasts an `ORDER` when it has heard
  messages not yet sequenced, at most once every `min(30 s, grace / 4)`.
  One host signature covers the whole batch (up to 10 entries per packet).
  An `ORDER` with `n = 0` is the host's heartbeat: it doesn't extend the
  chain, and its `first_seq` says where the chain is.
- **Chain.** `head_n = BLAKE3("commx-radio-chain-v1" || head_{n-1} || BE24(first_seq) || n || entries)`,
  starting from `head_0` (§18.2). For each `ORDER`, a member checks that it
  continues its chain and that the host signature is valid, then confirms
  the listed messages it holds. An `ORDER` that arrives ahead of a gap is
  held until the gap is filled. Each node keeps the head at every `ORDER`
  boundary.
- **Missing pieces aren't attacks.** Radio loses packets, so a missing `ORDER`
  or a listed message the member never heard is a gap. The member asks for it
  with `REPAIR` and does not nuke.
- **Contradictions are.** A member MUST nuke the room when:
  - a signature fails on a packet that decrypted;
  - an `ORDER` lists a hash that differs from the packet it holds for that
    `(sender, ctr)`;
  - another member's `seen_seq` / `seen_head` contradicts its own chain at
    that sequence number, or names a position that isn't an `ORDER`
    boundary in its chain. That catches equivocation, as soon as the
    victim's view is reported in any signed packet. Positions ahead of its
    own are remembered and checked once it gets there;
  - an `ORDER` covering positions it already has doesn't reproduce the same
    heads (the host signed two orders for the same place);
  - (host) a member reports a chain position the host never made.

  Only packets whose sender is authenticated count here: signed packets for
  everyone, and `BEAT` / `REPAIR` for the host, which can check their MACs.
  Any room member can still nuke the room this way, as on IP.
- **Repair.**
  - A member that is missing listed messages, holds `ORDER`s ahead of a gap,
    or hears any packet whose `seen_seq` is ahead of its own sends a `REPAIR`
    at most once per `min(30 s, grace / 4)`. The `REPAIR` lists the missing
    packets, and its own header's `seen_seq` asks for the `ORDER`s after it.
  - Any node holding a requested packet MAY rebroadcast it byte for byte,
    since packets authenticate themselves. It also rebroadcasts the next 3
    `ORDER`s after the requester's `seen_seq`.
  - It waits a random `0 – min(10 s, grace / 8)` first, and skips the
    rebroadcast if it hears someone else's.
  - Replay protection doesn't block repairs: a packet older than the replay
    window is still accepted if it is a listed message the node is missing,
    or the `ORDER` the chain needs next. Such packets never count as proof
    of life.
  - Repairs count against the airtime budget like anything else.
  - Repair also covers members who can hear the host but not each other.
- **Retries.** An author rebroadcasts its own unconfirmed `MSG` after
  `2 × min(30 s, grace / 4)`, then on a backoff capped at 4 × that, up to 8
  times. A member holding someone else's unconfirmed `MSG` passes it on
  (with the repair delay) after two `ORDER`s that don't list it.
- **Silent drops (OPEN-1)** mostly disappear: other members hear a message
  directly, so a host that never orders it is caught. A `MSG` still
  unconfirmed after three `ORDER`s (or, for the author, three retries) is
  flagged to the user.

### 18.6 Liveness

Grace windows are minutes, not seconds: default 20 minutes (`--radio-grace`).
A member sends a `BEAT` every `grace / 6` unless it sent a packet of its own
in that interval (rebroadcasts don't count: they prove nothing about the
sender). Six beats per window keep a live member in the room at 30% packet
loss with probability 1 − 0.3⁶ ≈ 99.93% per window. The host's heartbeat is
an empty `ORDER` on the same schedule. Any fresh authenticated packet counts
as proof of life; replayed ones don't. The kill rules are §12.2's, with
"heard from within the grace window" as the meaning of "up". Members only
watch the host; the host watches everyone.

When the host removes a member, it sends `REMOVE`, then the `REKEY`s
(sealed under the old epoch), and switches to the new epoch after the last
one. A member that missed its `REKEY` keeps talking under the old epoch;
the host still holds that epoch's key for receiving, notices, and resends
that member's `REKEY` (at most once per `min(30 s, grace / 4)`). Nodes keep
two epochs' keys. One removal is in flight at a time.

The host's `NUKE` is sent twice, outside the airtime budget: it is the last
thing the room ever sends.

Rough airtime at SF9 for a member: beats every 3⅓ minutes cost about 5 s
per hour, leaving roughly 27 full messages per hour under a 1% duty cycle.
The host also spends airtime on `ORDER` packets and repairs, so it SHOULD
be the node with the best antenna and the most generous budget. Nodes keep
a sliding one-hour window of airtime used and never exceed their budget
(`--radio-budget`, percent).

### 18.7 Radio adapters

The profile only needs "broadcast a packet of up to MTU bytes" and "receive
packets". Planned adapters:

| adapter | hops | status | notes |
|---|---|---|---|
| RNode / KISS over USB serial (`rnode:`) | 1 | implemented, not yet tested on hardware | Raw LoRa: full control of the packet and airtime. The host sets frequency, bandwidth, SF, CR and TX power over KISS, then sends `CMD_DATA` frames. Unix only for now. |
| UDP to fixed peers with simulated loss (`udp:`) | — | implemented | Drives the whole profile on one machine. |
| Meshtastic over serial (private app port 256) | multi-hop | planned | The mesh rebroadcasts for range. Meshtastic adds its own header with node ids, which leaks who transmits; its own channel encryption is extra, not relied on. |

### 18.8 Open questions

- **Joining over the air:** a QR-code room card with a single-use token,
  answered by an over-the-air version of §9.1 split over 3–4 packets.
- **Bridging:** a room where some members are on IP and others on radio. It
  needs authors to sign both formats, or a host-signed relay with weaker
  guarantees.
- **Compression:** a short-text compressor such as smaz or Unishox, which
  typically saves 30–50% on short English text.
- **Forward secrecy:** a hash ratchet per epoch (OPEN-5) costs nothing on the
  air and should come with this profile from the start.
