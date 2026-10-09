// AudioWorklet processors for commx calls (loaded with audioWorklet.addModule).
// Capture: microphone → 20 ms (960-sample) mono blocks posted to the page.
// Player: per-speaker jitter buffers, mixed into one output.

const FRAME = 960; // 20 ms at 48 kHz

class Capture extends AudioWorkletProcessor {
  constructor() {
    super();
    this.buf = new Float32Array(FRAME);
    this.n = 0;
  }

  process(inputs) {
    const ch = inputs[0] && inputs[0][0];
    if (ch) {
      for (let i = 0; i < ch.length; i++) {
        this.buf[this.n++] = ch[i];
        if (this.n === FRAME) {
          this.port.postMessage(this.buf, [this.buf.buffer]);
          this.buf = new Float32Array(FRAME);
          this.n = 0;
        }
      }
    }
    return true;
  }
}

// Start a speaker after 60 ms is buffered; cap latency at 300 ms.
const PRIME = 3 * FRAME;
const MAX_BUFFERED = 15 * FRAME;
const TRIM_TO = 5 * FRAME;

class Player extends AudioWorkletProcessor {
  constructor() {
    super();
    this.streams = new Map(); // name -> { q: Float32Array[], off, queued, primed }
    this.port.onmessage = (ev) => {
      const { name, pcm, drop } = ev.data;
      if (drop) {
        this.streams.delete(name);
        return;
      }
      let s = this.streams.get(name);
      if (!s) {
        s = { q: [], off: 0, queued: 0, primed: false };
        this.streams.set(name, s);
      }
      s.q.push(pcm);
      s.queued += pcm.length;
      if (s.queued > MAX_BUFFERED) {
        while (s.queued > TRIM_TO && s.q.length > 1) {
          const old = s.q.shift();
          s.queued -= old.length - s.off;
          s.off = 0;
        }
      }
    };
  }

  process(_inputs, outputs) {
    const out = outputs[0][0];
    out.fill(0);
    for (const s of this.streams.values()) {
      if (!s.primed) {
        if (s.queued < PRIME) continue;
        s.primed = true;
      }
      for (let i = 0; i < out.length; i++) {
        if (!s.q.length) {
          s.primed = false; // underrun: re-buffer before playing again
          break;
        }
        const cur = s.q[0];
        out[i] += cur[s.off++];
        s.queued--;
        if (s.off === cur.length) {
          s.q.shift();
          s.off = 0;
        }
      }
    }
    for (let i = 0; i < out.length; i++) out[i] = Math.max(-1, Math.min(1, out[i]));
    return true;
  }
}

registerProcessor('cx-capture', Capture);
registerProcessor('cx-player', Player);
