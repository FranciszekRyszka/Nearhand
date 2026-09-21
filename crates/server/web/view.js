// The web viewer: see and control a device from the browser.
//
// The session with the agent is Rust compiled to WebAssembly (`Viewer`):
// the same QUIC connection a native viewer makes, end-to-end encrypted to
// the agent's key. This page carries its packets through the server's
// relay — over WebTransport where the browser and the network have it,
// else over a WebSocket on the console's own port — decodes the video with
// WebCodecs, draws it, and sends the keyboard and mouse over the picture
// back.
//
// Keys go by position (`KeyboardEvent.code`), so the device's own layout
// applies. What the browser keeps for itself — Ctrl+W, Ctrl+T, Alt+Tab —
// stays with the browser, except in full screen, where the Keyboard Lock
// API (where the browser has it) sends those too.
//
// Opened from the console as /view?device=<device row id>, signed in.
"use strict";

import init, { Viewer, introduction_request, introduction_answer } from "/pkg/nearhand_web.js";

const $ = (id) => document.getElementById(id);
const status = (text, error = false) => {
  $("status").textContent = text;
  $("status").className = error ? "error" : "";
  $("status").hidden = false;
};

async function api(method, path) {
  const response = await fetch("/api/v1" + path, { method, credentials: "same-origin" });
  const body = await response.json().catch(() => ({}));
  if (response.status === 401) throw new Error("Sign in to the console first.");
  if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
  return body;
}

const hexBytes = (hex) => new Uint8Array(hex.match(/../g).map((b) => parseInt(b, 16)));

let viewer = null;
let link = null;
/// The console's row for the device, from the page's address: what a new
/// grant is asked for with.
let device = null;

async function main() {
  device = new URLSearchParams(location.search).get("device");
  if (!device) throw new Error("No device given: open the viewer from the console's device list.");
  if (!("VideoDecoder" in window)) {
    throw new Error("This browser lacks WebCodecs; use a current Chrome, Edge or Firefox, or the native viewer.");
  }
  status("Loading…");
  await init();

  status("Asking the server for access…");
  const granted = await api("POST", `/devices/${encodeURIComponent(device)}/grant`);
  $("device").textContent = `${granted.device_id} · ${granted.role}`;

  await connect(granted);
}

/// Reach the device and start a session, with the grant and — where the
/// device asks for both — its access password as well.
async function connect(granted, password) {
  status("Reaching the device…");
  link = await reach(granted.device_id);
  // The server names the key; the grant says which one it must be.
  if (link.fingerprint !== granted.fingerprint) {
    link.close();
    throw new Error("The server answered with another device's key.");
  }

  if (!keyIsTheOneSeenBefore(granted.device_id, link.fingerprint)) {
    link.close();
    throw new Error("Stopped: this device answered with another key than last time.");
  }

  viewer = new Viewer(link.fingerprint, granted.grant, password, 60);
  status("Connecting to the device…");
  run(link, viewer, granted, password);
}

/// How long to keep trying to get back to a device that went away. The
/// service moving its agent to the session someone just signed in to takes
/// seconds; a restart of the service, a few more.
const COME_BACK_FOR_MS = 120_000;

/// The agent went away saying it may be back — the service moving it to a
/// new session, or restarting — or the link was lost. Ask the server for a
/// new grant, since each is good once, and connect again, for a while.
async function comeBack(password, reason) {
  const until = Date.now() + COME_BACK_FOR_MS;
  let wait = 1000;
  for (;;) {
    status(`${reason[0].toUpperCase()}${reason.slice(1)} — trying again…`);
    await new Promise((resolve) => setTimeout(resolve, wait));
    try {
      const granted = await api("POST", `/devices/${encodeURIComponent(device)}/grant`);
      await connect(granted, password);
      return;
    } catch (e) {
      if (Date.now() >= until) {
        $("screen").hidden = true;
        status(`Could not get back to the device: ${e.message}`, true);
        return;
      }
      wait = Math.min(wait * 2, 10_000);
    }
  }
}

/// A device's ID is made from its key, but ten digits are not many: a
/// server willing to grind keys could find another that matches. So this
/// browser remembers which key each device had, and says so if it changes
/// — which a reinstall does not do, since that changes the ID too.
///
/// Kept per browser, in this console's own storage; losing it costs one
/// "seen for the first time" per device. Private windows and blocked
/// storage simply remember nothing.
function keyIsTheOneSeenBefore(deviceId, fingerprint) {
  let seen = null;
  try {
    seen = localStorage.getItem(`nearhand.device.${deviceId}`);
  } catch (e) {
    console.warn("no storage for device keys; not checking", e);
    return true;
  }
  if (seen === null || seen === fingerprint) return true;
  return window.confirm(
    [
      `${deviceId} answered with another key than last time.`,
      "",
      `was:  ${seen}`,
      `now:  ${fingerprint}`,
      "",
      "A device's ID is made from its key, so this is not a reinstall — that",
      "would change the ID too. Either the server introduced another machine,",
      "or something is standing between this browser and the device.",
      "",
      "Connect anyway, and remember the new key?",
    ].join("\n"),
  );
}

/// Write the key down once the device has actually answered with it.
function rememberKey(deviceId, fingerprint) {
  try {
    localStorage.setItem(`nearhand.device.${deviceId}`, fingerprint);
  } catch (e) {
    console.warn("could not remember the device's key", e);
  }
}

/// Reach the device through the server's relay: over WebTransport where
/// that works, else over a WebSocket, which any browser and any network
/// that reaches the console can carry.
///
/// `?transport=tcp` asks for the WebSocket straight away, for testing.
async function reach(deviceId) {
  const asked = new URLSearchParams(location.search).get("transport");
  if (asked !== "tcp" && "WebTransport" in window) {
    try {
      return await overWebTransport(deviceId);
    } catch (e) {
      // UDP blocked, or the certificate refused: TCP still goes.
      console.warn("WebTransport did not work; falling back to TCP", e);
      status("Reaching the device over TCP…");
    }
  }
  return await overWebSocket(deviceId);
}

async function overWebTransport(deviceId) {
  const web = await api("GET", "/webtransport");
  const transport = new WebTransport(web.url, {
    serverCertificateHashes: web.certificate_hashes.map((h) => ({ algorithm: "sha-256", value: hexBytes(h) })),
  });
  await transport.ready;
  const stream = await transport.createBidirectionalStream();
  const writer = stream.writable.getWriter();
  await writer.write(introduction_request(deviceId));
  await writer.close();
  const reader = stream.readable.getReader();
  const parts = [];
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    parts.push(value);
  }
  const fingerprint = introduction_answer(join(parts));
  const datagrams = transport.datagrams.writable.getWriter();
  return {
    over: "WebTransport",
    fingerprint,
    send: (packet) => datagrams.write(packet).catch(() => {}),
    onPacket: (take) => {
      (async () => {
        const reader = transport.datagrams.readable.getReader();
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          take(value);
        }
      })().catch(() => {});
    },
    close: () => transport.close(),
    closed: transport.closed,
  };
}

async function overWebSocket(deviceId) {
  const url = new URL("/api/v1/relay", location.href);
  url.protocol = url.protocol === "http:" ? "ws:" : "wss:";
  const socket = new WebSocket(url);
  socket.binaryType = "arraybuffer";
  const answer = new Promise((resolve, reject) => {
    socket.addEventListener("open", () => socket.send(introduction_request(deviceId)), { once: true });
    socket.addEventListener("message", (event) => resolve(new Uint8Array(event.data)), { once: true });
    socket.addEventListener("error", () => reject(new Error("the server did not take the connection")), { once: true });
    socket.addEventListener("close", () => reject(new Error("the server closed the connection")), { once: true });
  });
  const fingerprint = introduction_answer(await answer);
  return {
    over: "TCP",
    fingerprint,
    send: (packet) => {
      if (socket.readyState === WebSocket.OPEN) socket.send(packet);
    },
    onPacket: (take) => {
      socket.addEventListener("message", (event) => take(new Uint8Array(event.data)));
    },
    close: () => socket.close(),
    closed: new Promise((resolve) => socket.addEventListener("close", resolve, { once: true })),
  };
}

/// One buffer from the parts of a stream.
function join(parts) {
  const whole = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    whole.set(p, at);
    at += p.length;
  }
  return whole;
}

function run(link, viewer, granted, password) {
  const role = granted.role;
  // This session got as far as the picture: a loss after that is worth
  // coming back from; a failure before it is reported as it is.
  let established = false;
  const decoder = new Decoder(viewer);
  const clipboard = new ClipboardSync(viewer);
  let timer = null;
  let frames = 0;
  let closed = false;

  const pump = () => {
    let packet;
    while ((packet = viewer.transmit())) link.send(packet);
    let event;
    while ((event = viewer.event())) handle(event);
    clearTimeout(timer);
    const wait = viewer.wakeup_in_ms();
    if (wait !== undefined && !closed) {
      timer = setTimeout(() => {
        viewer.tick();
        pump();
      }, Math.max(1, wait));
    }
  };

  const handle = (event) => {
    switch (event.type) {
      case "connected":
        // It answered with the key the server named: worth remembering.
        rememberKey(granted.device_id, link.fingerprint);
        status("Connected; waiting to be let in…");
        break;
      case "awaiting":
        status("Waiting for the person at the device to allow the session…");
        break;
      case "monitors":
        established = true;
        showMonitors(event.monitors, viewer, pump);
        break;
      case "frame":
        frames++;
        decoder.decode(event);
        break;
      case "cursor":
        showCursor(event);
        break;
      case "cursor_visible":
        $("screen").dataset.pointer = event.visible ? "" : "hidden";
        applyCursor();
        break;
      case "clipboard":
        clipboard.fromDevice(event.text);
        break;
      case "closed":
        closed = true;
        link.close();
        if (event.may_return && established) {
          // The last picture stays up while the device comes back.
          comeBack(password, event.reason);
          break;
        }
        status(event.reason, !/ended/.test(event.reason));
        $("screen").hidden = true;
        break;
      case "password_needed": {
        // The device wants its access password as well as the grant, and
        // nothing has been presented yet — so the grant is still good, and
        // asking here costs only this connection.
        closed = true;
        link.close();
        const password = window.prompt(
          "This device asks for its access password as well as your access to it.",
        );
        if (!password) {
          status("This device needs its access password as well as a grant.", true);
          break;
        }
        status("Connecting again, with the password…");
        connect(granted, password).catch((e) => status(e.message, true));
        break;
      }
    }
  };

  link.onPacket((packet) => {
    viewer.receive(packet);
    pump();
  });

  link.closed
    .then(() => !closed && status("The server ended the session.", true))
    .catch((e) => !closed && status(`Connection lost: ${e.message}`, true));

  // The way in is worth seeing: TCP means UDP did not get through, and
  // costs some smoothness on a lossy link.
  const over = link.over === "TCP" ? " · over TCP" : "";
  setInterval(() => {
    if (closed) return;
    $("stats").textContent = `${frames} fps · ${viewer.rtt_ms().toFixed(0)} ms round trip${over}`;
    frames = 0;
  }, 1000);

  $("leave").onclick = () => {
    viewer.close();
    pump();
    setTimeout(() => (location.href = "/"), 300);
  };
  if (role === "view") {
    // The agent ignores a watcher's keyboard and mouse; say so.
    $("device").textContent += " (watching only)";
    $("cad").hidden = true;
    $("type").hidden = true;
  }
  attachInput(viewer, pump, clipboard);
  pump();
}

/// The keyboard and mouse over the picture, to the device.
function attachInput(viewer, pump, clipboard) {
  const canvas = $("screen");
  const send = (action) => {
    action();
    pump();
  };
  const at = (event) => {
    const rect = canvas.getBoundingClientRect();
    const x = ((event.clientX - rect.left) / rect.width) * canvas.width;
    const y = ((event.clientY - rect.top) / rect.height) * canvas.height;
    return [x, y];
  };
  canvas.addEventListener("pointermove", (e) => {
    const [x, y] = at(e);
    send(() => viewer.mouse_move(x, y, canvas.width, canvas.height));
  });
  canvas.addEventListener("pointerdown", (e) => {
    canvas.focus();
    canvas.setPointerCapture(e.pointerId);
    const [x, y] = at(e);
    send(() => {
      viewer.mouse_move(x, y, canvas.width, canvas.height);
      viewer.mouse_button(e.button, true);
    });
    e.preventDefault();
  });
  canvas.addEventListener("pointerup", (e) => {
    send(() => viewer.mouse_button(e.button, false));
    e.preventDefault();
  });
  canvas.addEventListener("contextmenu", (e) => e.preventDefault());
  canvas.addEventListener("wheel", (e) => {
    // Notches: a wheel detent is about 100 pixels, or 3 lines.
    const per = e.deltaMode === 0 ? 100 : e.deltaMode === 1 ? 3 : 1;
    send(() => viewer.wheel(e.deltaX / per, e.deltaY / per));
    e.preventDefault();
  }, { passive: false });

  const key = (e, down) => {
    // Ctrl+Alt+End stands for Ctrl+Alt+Del, which the local system keeps.
    if (down && e.code === "End" && e.ctrlKey && e.altKey) {
      send(() => viewer.secure_attention());
    } else if (!viewer.key(e.code, down) && down && e.key.length === 1) {
      viewer.text(e.key);
    }
    pump();
    e.preventDefault();
  };
  canvas.addEventListener("keydown", (e) => key(e, true));
  canvas.addEventListener("keyup", (e) => key(e, false));

  // Whatever is held when the picture loses focus would be let go of
  // elsewhere: let go of it on the device too.
  canvas.addEventListener("blur", () => send(() => viewer.release_all()));
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) send(() => viewer.release_all());
  });
  canvas.addEventListener("focus", () => clipboard.toDevice());

  $("cad").onclick = () => {
    send(() => viewer.secure_attention());
    canvas.focus();
  };
  // Says what happened on the button itself for a moment: the status line
  // is for the session, and would stay over the picture.
  const typed = (label) => {
    $("type").textContent = label;
    setTimeout(() => ($("type").textContent = "Type clipboard"), 2500);
  };
  $("type").onclick = async () => {
    let text;
    try {
      text = await navigator.clipboard.readText();
    } catch (e) {
      console.warn("clipboard:", e);
      typed("Clipboard not readable");
      return;
    } finally {
      canvas.focus();
    }
    if (!text) {
      typed("Clipboard is empty");
      return;
    }
    let cut = false;
    send(() => { cut = viewer.type_text(text); });
    typed(cut ? "Typed the first part" : "Typed");
  };
  $("full").onclick = async () => {
    const main = document.querySelector("main");
    if (document.fullscreenElement) {
      await document.exitFullscreen();
      return;
    }
    await main.requestFullscreen();
    // Where the browser offers it, full screen also takes Alt+Tab, the
    // Windows key and the like, instead of leaving them to this machine.
    if (navigator.keyboard && navigator.keyboard.lock) navigator.keyboard.lock().catch(() => {});
    canvas.focus();
  };
}

/// The device's pointer, shown as this browser's own over the picture.
let cursorUrl = null;
function showCursor({ width, height, hot_x, hot_y, rgba }) {
  const image = document.createElement("canvas");
  image.width = width;
  image.height = height;
  image.getContext("2d").putImageData(new ImageData(new Uint8ClampedArray(rgba), width, height), 0, 0);
  // Browsers take cursors up to 128 pixels; the default arrow beyond that.
  cursorUrl = width <= 128 && height <= 128 ? `url(${image.toDataURL()}) ${hot_x} ${hot_y}, default` : "default";
  applyCursor();
}
function applyCursor() {
  const canvas = $("screen");
  canvas.style.cursor = canvas.dataset.pointer === "hidden" ? "none" : cursorUrl || "default";
}

/// Clipboard text both ways. The device's copies go to this browser's
/// clipboard; this browser's go to the device when the picture gets focus —
/// browsers let a page read the clipboard only with permission, and only
/// while it has focus.
class ClipboardSync {
  constructor(viewer) {
    this.viewer = viewer;
    this.last = null;
    this.pending = null;
  }

  fromDevice(text) {
    this.last = text;
    if (!navigator.clipboard) return;
    navigator.clipboard.writeText(text).catch(() => {
      // Without focus the write fails: try again when it comes back.
      this.pending = text;
    });
  }

  async toDevice() {
    if (this.pending !== null) {
      const text = this.pending;
      this.pending = null;
      await navigator.clipboard.writeText(text).catch(() => {});
      return;
    }
    if (!navigator.clipboard || !navigator.clipboard.readText) return;
    try {
      const text = await navigator.clipboard.readText();
      if (text && text !== this.last) {
        this.last = text;
        this.viewer.clipboard(text);
      }
    } catch {
      // No permission: the clipboard stays this browser's.
    }
  }
}

function showMonitors(monitors, viewer, pump) {
  const select = $("monitor");
  select.replaceChildren(...monitors.map((m) => {
    const option = document.createElement("option");
    option.value = m.id;
    option.textContent = `${m.width}×${m.height}${m.primary ? " (primary)" : ""}`;
    return option;
  }));
  select.hidden = monitors.length < 2;
  const first = monitors.find((m) => m.primary) || monitors[0];
  select.value = first.id;
  select.onchange = () => {
    viewer.start_video(Number(select.value));
    pump();
  };
  status("Waiting for the picture…");
  viewer.start_video(first.id);
  pump();
}

/// WebCodecs, fed Annex B H.264, drawing each frame onto the canvas.
class Decoder {
  constructor(viewer) {
    this.viewer = viewer;
    this.canvas = $("screen");
    this.context = this.canvas.getContext("2d");
    this.decoder = null;
    this.codec = null;
  }

  decode(frame) {
    if (frame.keyframe && frame.codec && (!this.decoder || frame.codec !== this.codec)) {
      this.open(frame.codec);
    }
    // Until a keyframe has configured it, a decoder can do nothing.
    if (!this.decoder || this.decoder.state !== "configured") return;
    try {
      this.decoder.decode(new EncodedVideoChunk({
        type: frame.keyframe ? "key" : "delta",
        timestamp: frame.timestamp,
        data: frame.data,
      }));
    } catch (e) {
      this.fail(e);
    }
  }

  open(codec) {
    this.close();
    this.codec = codec;
    this.decoder = new VideoDecoder({
      output: (picture) => this.draw(picture),
      error: (e) => this.fail(e),
    });
    // No description: the stream is Annex B, parameter sets in band.
    this.decoder.configure({ codec, optimizeForLatency: true, hardwareAcceleration: "no-preference" });
  }

  draw(picture) {
    if (this.canvas.width !== picture.displayWidth || this.canvas.height !== picture.displayHeight) {
      this.canvas.width = picture.displayWidth;
      this.canvas.height = picture.displayHeight;
    }
    this.context.drawImage(picture, 0, 0);
    picture.close();
    if (this.canvas.hidden) {
      this.canvas.hidden = false;
      $("status").hidden = true;
    }
  }

  fail(e) {
    console.warn("decoder:", e);
    this.close();
    this.viewer.request_keyframe();
  }

  close() {
    if (this.decoder && this.decoder.state !== "closed") this.decoder.close();
    this.decoder = null;
  }
}

main().catch((e) => {
  status(e.message || String(e), true);
  if (link) link.close();
});
