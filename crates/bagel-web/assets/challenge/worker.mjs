const MODULE = "/__bagel/static/solver.wasm";
const SLICE_MS = 40;

const decode = (text) =>
  Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/")), (ch) =>
    ch.charCodeAt(0),
  );
const encode = (bytes) =>
  btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

const PROBES = [
  "OffscreenCanvas", "ImageBitmap", "createImageBitmap", "WebGL2RenderingContext", "GPU",
  "navigator.gpu", "navigator.hardwareConcurrency", "navigator.userAgentData",
  "navigator.storage", "navigator.locks", "navigator.permissions", "navigator.connection",
  "caches", "indexedDB", "BroadcastChannel", "MessageChannel", "WebSocket", "EventSource",
  "FileReaderSync", "ImageData", "Path2D", "FontFace", "self.fonts",
  "WebAssembly.instantiateStreaming", "WebAssembly.compileStreaming", "CompressionStream",
  "DecompressionStream", "TextDecoderStream", "crypto.subtle", "crypto.randomUUID",
  "performance.memory", "performance.timeOrigin", "scheduler", "requestIdleCallback",
  "importScripts", "WorkerGlobalScope", "DedicatedWorkerGlobalScope", "WorkerNavigator",
  "WorkerLocation", "PushManager", "Notification", "PerformanceObserver", "ReportingObserver",
  "TrustedTypePolicyFactory", "WebTransport", "RTCPeerConnection", "AudioData", "VideoFrame",
];

const present = (path) => {
  try {
    return path.split(".").reduce((scope, part) => scope?.[part], globalThis) !== undefined;
  } catch {
    return false;
  }
};

const quirk = (check) => {
  try {
    return check() ? 1 : 0;
  } catch {
    return 0;
  }
};

const probe = () => {
  let lo = 0;
  let hi = 0;
  PROBES.forEach((path, bit) => {
    if (!present(path)) return;
    if (bit < 32) lo |= 1 << bit;
    else hi |= 1 << (bit - 32);
  });
  const cores = Math.min(15, Math.max(0, Number(navigator.hardwareConcurrency) || 0));
  const heap = Number(performance.memory?.jsHeapSizeLimit) / 1048576;
  const memory = heap >= 512 ? Math.min(7, 1 + Math.floor(Math.log2(heap / 512))) : 0;
  hi |= cores << 16;
  hi |= memory << 20;
  hi |= quirk(() => Object.getOwnPropertyDescriptor(navigator, "userAgent") === undefined) << 23;
  hi |= quirk(() => typeof Error.captureStackTrace === "function") << 24;
  hi |= quirk(() => Function.prototype.toString.call(fetch).includes("native code")) << 25;
  hi |= quirk(() => String(new Error().stack).trimStart().startsWith("Error")) << 26;
  hi |= quirk(() => Intl.DateTimeFormat().resolvedOptions().timeZone === "UTC") << 27;
  hi |= Math.min(3, String(navigator.language ?? "").length) << 28;
  return [hi >>> 0, lo >>> 0];
};

self.onmessage = async ({ data }) => {
  self.onmessage = null;

  try {
    const handoff = decode(data);
    const { instance } = await WebAssembly.instantiateStreaming(fetch(MODULE));
    const { memory, buf, unpack, solve, seal } = instance.exports;
    const base = buf();
    const view = () => new Uint8Array(memory.buffer);
    view().set(handoff, base);
    if (unpack(handoff.length) < 0) throw new Error("Invalid challenge handoff");

    const started = performance.now();
    let nonce = 0n;
    let found = -1n;
    let batch = 16;
    while (found < 0n) {
      const before = performance.now();
      found = solve(nonce, batch);
      nonce += BigInt(batch);
      const took = Math.max(performance.now() - before, 1);
      batch = Math.max(1, Math.min(1 << 20, Math.round((batch * SLICE_MS) / took)));
      self.postMessage({ type: "progress", elapsed: performance.now() - started });
      await new Promise((resolve) => setTimeout(resolve, 0));
    }

    const iv = crypto.getRandomValues(new Uint32Array(1))[0];
    const [hi, lo] = probe();
    const length = seal(found, iv, hi, lo);
    self.postMessage({ type: "proof", proof: encode(view().subarray(base, base + length)) });
  } catch {
    self.postMessage({ type: "error" });
  } finally {
    self.close();
  }
};
