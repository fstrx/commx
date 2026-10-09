// commx web client: moves bytes between the WebSocket and the WebAssembly
// room member, and renders its events. All crypto happens in WebAssembly.
// Untrusted text is only ever assigned via textContent (never innerHTML).
import init, { WebMember } from './commx_web.js';

const $ = (id) => document.getElementById(id);
const NAME_COLORS = ['#82aaff', '#ffb464', '#c88cff', '#ff82b4', '#78d2e6', '#e6dc6e'];

// The invite rides in the URL fragment (never sent to any server). Read it,
// then erase it from the address bar and history: it's single use anyway.
const invite = decodeURIComponent(location.hash.slice(1)).trim();
history.replaceState(null, '', location.pathname);

let member = null;
let ws = null;
let inRoom = false;

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

function wipe() {
  // Drop everything this page showed about the room.
  $('lines').replaceChildren();
  $('members').textContent = '';
  $('room-name').textContent = '';
  $('room-meta').textContent = '';
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
      $('msg').focus();
      break;
    case 'members':
      $('members').textContent = 'in the room: ' + e.members.join(', ');
      break;
    case 'line':
      addLine(e);
      break;
    case 'nuked':
      inRoom = false;
      wipe();
      $('welcome').hidden = true;
      $('room').hidden = true;
      $('ended').hidden = false;
      $('ended-reason').textContent = e.reason;
      if (ws) ws.close();
      break;
  }
}

function pump() {
  if (!member) return;
  // Only drain outgoing bytes once they can be sent; until the socket is
  // open they stay queued inside the member (dropping them stalls the join).
  if (ws && ws.readyState === WebSocket.OPEN) {
    const out = member.outgoing();
    if (out.length) ws.send(out);
  }
  for (const e of JSON.parse(member.events())) handle(e);
}

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
      addLine({ system: true, text: String(err.message || err), ts_min: Date.now() / 60000 });
    }
    pump();
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
