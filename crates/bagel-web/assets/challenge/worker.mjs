const VERSION = new URL(import.meta.url).search;
const GPU = `/__bagel/static/gpu.mjs${VERSION}`;
const SLICE_MS = 40;
const GPU_BUDGET_MS = 2000;

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

const progress = (started) =>
  self.postMessage({ type: "progress", elapsed: performance.now() - started });

async function solveOnGpu(keyBytes, difficulty, started, budgetMs) {
  if (!navigator.gpu) return null;
  try {
    const { createGpuSolver } = await import(GPU);
    const solver = await createGpuSolver();
    if (!solver) return null;
    return await solver.solve(keyBytes, difficulty, () => progress(started), budgetMs);
  } catch {
    return null;
  }
}

async function solveOnCpu(solve, started) {
  let nonce = 0n;
  let found = -1n;
  let batch = 16;
  while (found < 0n) {
    const before = performance.now();
    found = solve(nonce, batch);
    nonce += BigInt(batch);
    const took = Math.max(performance.now() - before, 1);
    batch = Math.max(1, Math.min(1 << 20, Math.round((batch * SLICE_MS) / took)));
    progress(started);
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  return found;
}

self.onmessage = async ({ data }) => {
  self.onmessage = null;

  try {
    const handoff = decode(data.payload);
    const { instance } = await WebAssembly.instantiateStreaming(
      fetch(data.solver),
    );
    const { memory, buf, unpack, key, solve, seal } = instance.exports;
    const base = buf();
    const view = () => new Uint8Array(memory.buffer);
    view().set(handoff, base);
    const levels = unpack(handoff.length);
    if (levels < 0) throw new Error("Invalid challenge handoff");
    const cpuLevel = levels & 0xff;
    const gpuLevel = levels >>> 8;
    const gpuRequired = gpuLevel === cpuLevel;

    const started = performance.now();
    let level = cpuLevel;
    let found = null;
    if (gpuLevel > 0) {
      const keyBytes = view().slice(base, base + key());
      const budgetMs = gpuRequired ? Infinity : GPU_BUDGET_MS;
      found = await solveOnGpu(keyBytes, gpuLevel, started, budgetMs);
      if (found !== null) level = gpuLevel;
    }
    if (found === null && gpuRequired) {
      self.postMessage({ type: "unsupported" });
      return;
    }
    if (found === null) found = await solveOnCpu(solve, started);

    const iv = crypto.getRandomValues(new Uint32Array(1))[0];
    const [hi, lo] = probe();
    const length = seal(found, iv, hi, lo, level);
    self.postMessage({ type: "proof", proof: encode(view().subarray(base, base + length)) });
  } catch {
    self.postMessage({ type: "error" });
  } finally {
    self.close();
  }
};
