// commx web client: moves bytes between the WebSocket and the WebAssembly
// room member, and renders its events. All crypto happens in WebAssembly.
// Untrusted text is only ever assigned via textContent (never innerHTML).
import init, { WebMember } from './commx_web.js';

const $ = (id) => document.getElementById(id);
const NAME_COLORS = ['#82aaff', '#ffb464', '#c88cff', '#ff82b4', '#78d2e6', '#e6dc6e'];
const MAX_FILE = 256 * 1024 * 1024;
// Socket backpressure: file chunks only top the buffer up to BULK_FILL, and
// voice is held back (the member drops stale frames) above MEDIA_LIMIT.
const BULK_FILL = 256 * 1024;
const MEDIA_LIMIT = 512 * 1024;

// The invite rides in the URL fragment (never sent to any server). Read it,
// then erase it from the address bar and history.
const invite = decodeURIComponent(location.hash.slice(1)).trim();
history.replaceState(null, '', location.pathname);

let member = null;
let ws = null;
let inRoom = false;
let call = null; // { participants, joined } from the member, or null
let audio = null; // live audio pipeline while we're in a call
let audioStarting = false; // startAudio() in flight: never run two pipelines
let bulkTimer = null;

function setStatus(text, bad = false) {
  $('status').textContent = text;
  $('status').className = bad ? 'warn' : 'dim';
}

function colorFor(name) {
  let h = 0;
  for (const c of name) h = (h * 31 + c.codePointAt(0)) | 0;
  return NAME_COLORS[Math.abs(h) % NAME_COLORS.length];
}

function hhmm(tsMin) {
  return new Date(tsMin * 60000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function humanSize(n) {
  if (n >= 1 << 20) return (n / (1 << 20)).toFixed(1) + ' MiB';
  if (n >= 1 << 10) return (n / 1024).toFixed(1) + ' KiB';
  return n + ' B';
}

function note(text) {
  addLine({ system: true, text, ts_min: Date.now() / 60000 });
}

function addLine(e) {
  const li = document.createElement('li');
  const ts = document.createElement('span');
  ts.className = 'ts';
  ts.textContent = hhmm(e.ts_min);
  li.append(ts);
  if (e.system) {
    const t = document.createElement('span');
    t.className = 'sys';
    t.textContent = '* ' + e.text;
    li.append(t);
  } else {
    const who = document.createElement('span');
    who.className = 'who' + (e.mine ? ' mine' : '');
    if (!e.mine) who.style.setProperty('color', colorFor(e.from));
    who.textContent = e.from;
    const t = document.createElement('span');
    t.textContent = e.text;
    li.append(who, t);
  }
  const box = $('lines');
  const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 40;
  box.append(li);
  if (atBottom) box.scrollTop = box.scrollHeight;
}

function renderFiles(list) {
  const ul = $('files');
  ul.replaceChildren();
  ul.hidden = list.length === 0;
  for (const f of list) {
    const li = document.createElement('li');
    const label = document.createElement('span');
    label.textContent = `#${f.no} ${f.name} (${humanSize(f.size)}) from ${f.from} — ${f.state}`;
    li.append(label);
    if (f.ready) {
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'small';
      b.textContent = 'Save';
      b.addEventListener('click', () => saveFile(f.no));
      li.append(b);
    }
    ul.append(li);
  }
}

function saveFile(no) {
  const bytes = member && member.file_bytes(no);
  if (!bytes) return;
  // The browser keeps its own copy once downloaded; this page only holds
  // the decrypted file until the room ends.
  const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = member.file_name(no) || 'file';
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function renderCall() {
  const btn = $('call-btn');
  const mute = $('mute-btn');
  if (!call) {
    btn.textContent = 'Call';
    $('call-info').textContent = '';
  } else {
    btn.textContent = call.joined ? 'Leave call' : 'Join call';
    $('call-info').textContent = '📞 ' + call.participants.join(', ');
  }
  btn.classList.toggle('danger', !!(call && call.joined));
  mute.hidden = !(call && call.joined);
  mute.textContent = audio && audio.muted ? 'Unmute' : 'Mute';
}

function wipe() {
  // Drop everything this page showed about the room.
  $('lines').replaceChildren();
  $('files').replaceChildren();
  $('members').textContent = '';
  $('room-name').textContent = '';
  $('room-meta').textContent = '';
  $('call-info').textContent = '';
}

async function onCall(c) {
  call = c;
  renderCall();
  if (c && c.joined && !audio && !audioStarting) {
    audioStarting = true;
    let a = null;
    try {
      a = await startAudio();
    } catch (err) {
      note('voice unavailable: ' + (err.message || err));
      try {
        if (member && call && call.joined) member.set_in_call(false);
      } catch (_) {}
      pump();
    }
    audioStarting = false;
    // We may have left the call (or the room) while the mic was starting.
    if (a && call && call.joined && member) {
      audio = a;
      note('microphone on — headphones avoid echo');
    } else if (a) {
      closeAudio(a);
    }
  } else if ((!c || !c.joined) && audio) {
    stopAudio();
  }
  renderCall();
}

function handle(e) {
  switch (e.ev) {
    case 'status':
      setStatus(e.text);
      break;
    case 'error':
      setStatus(e.msg, true);
      $('join-btn').disabled = false;
      break;
    case 'joined':
      inRoom = true;
      $('welcome').hidden = true;
      $('room').hidden = false;
      $('room-name').textContent = (e.is_dm ? '@' : '#') + e.name;
      $('room-meta').textContent =
        `host ${e.host} [${e.host_fp}] · kill switch: ${e.kill_mode}, ${e.grace_secs}s · you are ${e.me} [${e.fp}]`;
      renderCall();
      $('msg').focus();
      break;
    case 'members':
      $('members').textContent = 'in the room: ' + e.members.join(', ');
      break;
    case 'line':
      addLine(e);
      break;
    case 'files':
      renderFiles(e.list);
      break;
    case 'call':
      onCall(e.call);
      break;
    case 'nuked':
      inRoom = false;
      stopAudio();
      call = null;
      wipe();
      $('welcome').hidden = true;
      $('room').hidden = true;
      $('ended').hidden = false;
      $('ended-reason').textContent = e.reason;
      if (ws) ws.close();
      member = null;
      break;
  }
}

function pump() {
  if (!member) return;
  // Only drain outgoing bytes once they can be sent; until the socket is
  // open they stay queued inside the member (dropping them stalls the join).
  if (ws && ws.readyState === WebSocket.OPEN) {
    const buffered = ws.bufferedAmount;
    const budget = buffered < BULK_FILL ? BULK_FILL - buffered : 0;
    const out = member.outgoing(buffered < MEDIA_LIMIT, budget);
    if (out.length) ws.send(out);
  }
  const m = member;
  for (const e of JSON.parse(m.events())) handle(e);
  if (audio && member) playFrames(member.voice());
  // Keep uploading while chunks remain.
  if (member && member.bulk_pending() && !bulkTimer) {
    bulkTimer = setTimeout(() => {
      bulkTimer = null;
      pump();
    }, 10);
  }
}

// ---- voice -------------------------------------------------------------

async function startAudio() {
  if (!window.isSecureContext || !navigator.mediaDevices) {
    throw new Error('the browser only allows the microphone over https — ask the host to run commxd --web-tls');
  }
  if (typeof AudioEncoder === 'undefined' || typeof AudioDecoder === 'undefined') {
    throw new Error('this browser lacks WebCodecs audio (use a current Chrome, Edge, Firefox or Safari)');
  }
  const support = await AudioEncoder.isConfigSupported(encoderConfig());
  if (!support.supported) throw new Error('this browser has no Opus encoder');
  const stream = await navigator.mediaDevices.getUserMedia({
    audio: { channelCount: 1, echoCancellation: true, noiseSuppression: true, autoGainControl: true },
  });
  const ctx = new AudioContext({ sampleRate: 48000, latencyHint: 'interactive' });
  await ctx.audioWorklet.addModule('audio.js');
  const a = { ctx, stream, muted: false, decoders: new Map(), ts: 0 };
  a.capture = new AudioWorkletNode(ctx, 'cx-capture', { numberOfOutputs: 1, outputChannelCount: [1] });
  a.player = new AudioWorkletNode(ctx, 'cx-player', { numberOfInputs: 0, outputChannelCount: [1] });
  ctx.createMediaStreamSource(stream).connect(a.capture);
  a.capture.connect(ctx.destination); // silent; keeps the capture node pulled
  a.player.connect(ctx.destination);
  a.encoder = new AudioEncoder({
    output: (chunk) => {
      if (!member) return;
      const b = new Uint8Array(chunk.byteLength);
      chunk.copyTo(b);
      // Fixed-size frames go out either way; an oversized packet becomes an
      // empty one rather than a gap.
      try {
        member.send_voice(b.length <= 126 ? b : new Uint8Array(0));
      } catch (_) {}
      pump();
    },
    error: (err) => note('microphone encoder failed: ' + err.message),
  });
  a.encoder.configure(encoderConfig());
  // Continuous: muted still sends (silent) frames, so nobody learns when you talk.
  a.capture.port.onmessage = (ev) => {
    if (audio !== a || a.encoder.state !== 'configured') return;
    const pcm = a.muted ? new Float32Array(960) : ev.data;
    const data = new AudioData({ format: 'f32', sampleRate: 48000, numberOfFrames: 960, numberOfChannels: 1, timestamp: a.ts, data: pcm });
    a.ts += 20000;
    a.encoder.encode(data);
    data.close();
  };
  if (ctx.state === 'suspended') await ctx.resume();
  return a;
}

function encoderConfig() {
  return {
    codec: 'opus',
    sampleRate: 48000,
    numberOfChannels: 1,
    bitrate: 24000,
    bitrateMode: 'constant',
    opus: { frameDuration: 20000, application: 'voip', complexity: 5, usedtx: false, useinbandfec: false },
  };
}

function decoderFor(name) {
  let d = audio.decoders.get(name);
  if (d && d.state !== 'closed') return d;
  const player = audio.player;
  d = new AudioDecoder({
    output: (data) => {
      const pcm = new Float32Array(data.numberOfFrames);
      data.copyTo(pcm, { planeIndex: 0, format: 'f32-planar' });
      data.close();
      player.port.postMessage({ name, pcm }, [pcm.buffer]);
    },
    error: () => audio && audio.decoders.delete(name),
  });
  d.configure({ codec: 'opus', sampleRate: 48000, numberOfChannels: 1 });
  audio.decoders.set(name, d);
  return d;
}

// Frames from the member: [u8 name_len][name][u64 seq][u16 len][opus]...
const utf8 = new TextDecoder();
function playFrames(buf) {
  let i = 0;
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  while (i < buf.length) {
    const n = buf[i];
    const name = utf8.decode(buf.subarray(i + 1, i + 1 + n));
    i += 1 + n;
    const seq = Number(view.getBigUint64(i, true));
    const len = view.getUint16(i + 8, true);
    const opus = buf.slice(i + 10, i + 10 + len);
    i += 10 + len;
    if (!len) continue;
    try {
      decoderFor(name).decode(new EncodedAudioChunk({ type: 'key', timestamp: seq * 20000, data: opus }));
    } catch (_) {}
  }
}

function stopAudio() {
  if (!audio) return;
  const a = audio;
  audio = null;
  closeAudio(a);
}

function closeAudio(a) {
  for (const t of a.stream.getTracks()) t.stop();
  for (const d of a.decoders.values()) {
    try {
      d.close();
    } catch (_) {}
  }
  try {
    a.encoder.close();
  } catch (_) {}
  a.ctx.close();
}

// ---- connection --------------------------------------------------------

function connect(alias, password) {
  try {
    member = new WebMember(invite, alias, password);
  } catch (err) {
    setStatus(String(err.message || err), true);
    $('join-btn').disabled = false;
    return;
  }
  // Same origin as this page: the host that served it.
  const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(`${scheme}//${location.host}/ws`);
  ws.binaryType = 'arraybuffer';
  let opened = false;
  ws.onopen = () => {
    opened = true;
    pump();
  };
  ws.onmessage = (ev) => {
    if (!member) return;
    member.receive(new Uint8Array(ev.data));
    pump();
  };
  ws.onclose = () => {
    if (!opened) {
      // Never connected: blocked or refused, not a host drop.
      member = null;
      setStatus("couldn't connect to the host (connection refused or blocked by the browser)", true);
      $('join-btn').disabled = false;
      return;
    }
    if (member) {
      member.closed();
      pump();
    }
  };
  pump();
}

async function main() {
  await init();
  if (!invite.startsWith('cx1:') && !invite.startsWith('cx2:')) {
    $('no-invite').hidden = false;
    $('join-form').hidden = true;
    return;
  }
  const needsPassword = WebMember.needs_password(invite);
  $('password').hidden = $('password-label').hidden = !needsPassword;
  $('join-form').addEventListener('submit', (ev) => {
    ev.preventDefault();
    const alias = $('alias').value.trim();
    const password = $('password').value;
    if (!alias || (needsPassword && !password)) return;
    $('join-btn').disabled = true;
    setStatus(needsPassword ? 'checking password…' : 'connecting…');
    // Let the status paint before the (sub-second) password hashing.
    setTimeout(() => {
      connect(alias, needsPassword ? password : '');
      $('password').value = '';
    }, 20);
  });
  $('send-form').addEventListener('submit', (ev) => {
    ev.preventDefault();
    const text = $('msg').value;
    if (!text.trim() || !member) return;
    try {
      member.send_text(text);
      $('msg').value = '';
    } catch (err) {
      note(String(err.message || err));
    }
    pump();
  });
  $('file-btn').addEventListener('click', () => $('file-input').click());
  $('file-input').addEventListener('change', async () => {
    const f = $('file-input').files[0];
    $('file-input').value = '';
    if (!f || !member) return;
    if (f.size > MAX_FILE) return note('file too large (max 256 MiB)');
    try {
      const bytes = new Uint8Array(await f.arrayBuffer());
      member.send_file(f.name, bytes);
    } catch (err) {
      note(String(err.message || err));
    }
    pump();
  });
  $('call-btn').addEventListener('click', () => {
    if (!member) return;
    try {
      if (!call) member.start_call();
      else member.set_in_call(!call.joined);
    } catch (err) {
      note(String(err.message || err));
    }
    pump();
  });
  $('mute-btn').addEventListener('click', () => {
    if (audio) audio.muted = !audio.muted;
    renderCall();
  });
  $('leave-btn').addEventListener('click', () => {
    if (member) {
      member.leave();
      pump();
    }
  });
  window.addEventListener('beforeunload', (ev) => {
    if (inRoom) {
      ev.preventDefault();
      ev.returnValue = '';
    }
  });
  $('alias').focus();
}

main();
