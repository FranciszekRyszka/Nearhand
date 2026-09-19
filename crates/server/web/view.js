// The web viewer: watch a device from the browser.
//
// The session with the agent is Rust compiled to WebAssembly (`Viewer`):
// the same QUIC connection a native viewer makes, end-to-end encrypted to
// the agent's key. This page carries its packets over WebTransport through
// the server's relay, decodes the video with WebCodecs, and draws it.
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
let transport = null;

async function main() {
  const device = new URLSearchParams(location.search).get("device");
  if (!device) throw new Error("No device given: open the viewer from the console's device list.");
  if (!("WebTransport" in window) || !("VideoDecoder" in window)) {
    throw new Error("This browser lacks WebTransport or WebCodecs; use a current Chrome, Edge or Firefox, or the native viewer.");
  }
  status("Loading…");
  await init();

  status("Asking the server for access…");
  const granted = await api("POST", `/devices/${encodeURIComponent(device)}/grant`);
  $("device").textContent = `${granted.device_id} · ${granted.role}`;
  const web = await api("GET", "/webtransport");

  status("Reaching the device…");
  transport = new WebTransport(web.url, {
    serverCertificateHashes: web.certificate_hashes.map((h) => ({ algorithm: "sha-256", value: hexBytes(h) })),
  });
  await transport.ready;
  const fingerprint = await introduce(transport, granted.device_id);
  // The server names the key; the grant says which one it must be.
  if (fingerprint !== granted.fingerprint) throw new Error("The server answered with another device's key.");

  viewer = new Viewer(fingerprint, granted.grant, undefined, 60);
  status("Connecting to the device…");
  run(transport, viewer);
}

/// Ask the server to introduce this browser to the device; its key's
/// fingerprint, once the device has opened its way.
async function introduce(transport, deviceId) {
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
  const whole = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    whole.set(p, at);
    at += p.length;
  }
  return introduction_answer(whole);
}

function run(transport, viewer) {
  const writer = transport.datagrams.writable.getWriter();
  const decoder = new Decoder(viewer);
  let timer = null;
  let frames = 0;
  let closed = false;

  const pump = () => {
    let packet;
    while ((packet = viewer.transmit())) writer.write(packet).catch(() => {});
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
        status("Connected; waiting to be let in…");
        break;
      case "awaiting":
        status("Waiting for the person at the device to allow the session…");
        break;
      case "monitors":
        showMonitors(event.monitors, viewer, pump);
        break;
      case "frame":
        frames++;
        decoder.decode(event);
        break;
      case "closed":
        closed = true;
        status(event.reason, !/ended/.test(event.reason));
        $("screen").hidden = true;
        transport.close();
        break;
    }
  };

  (async () => {
    const reader = transport.datagrams.readable.getReader();
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      viewer.receive(value);
      pump();
    }
  })().catch(() => {});

  transport.closed
    .then(() => !closed && status("The server ended the session.", true))
    .catch((e) => !closed && status(`Connection lost: ${e.message}`, true));

  setInterval(() => {
    if (closed) return;
    $("stats").textContent = `${frames} fps · ${viewer.rtt_ms().toFixed(0)} ms round trip`;
    frames = 0;
  }, 1000);

  $("leave").onclick = () => {
    viewer.close();
    pump();
    setTimeout(() => (location.href = "/"), 300);
  };
  pump();
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
  if (transport) transport.close();
});
