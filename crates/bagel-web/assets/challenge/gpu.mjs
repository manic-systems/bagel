const WGSL_SHADER = `
struct Params {
  key0: u32,
  key1: u32,
  key2: u32,
  key3: u32,
  key4: u32,
  key5: u32,
  key6: u32,
  key7: u32,
  nonce_hi: u32,
  nonce_lo: u32,
  difficulty: u32,
  _pad: u32,
};

struct Result {
  found: atomic<u32>,
  nonce_hi: atomic<u32>,
  nonce_lo: atomic<u32>,
  _pad: u32,
};

@group(0) @binding(0) var<uniform> params: Params;
@group(0) @binding(1) var<storage, read_write> result: Result;

const K = array<u32, 64>(
  0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
  0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
  0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
  0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
  0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
  0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
  0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
  0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
  0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
  0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
  0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
  0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
  0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
  0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
  0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
  0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
);

fn rotr(x: u32, n: u32) -> u32 {
  return (x >> n) | (x << (32u - n));
}

@compute @workgroup_size(256)
fn main(@builtin(global_invocation_id) global_id: vec3<u32>) {
  let idx = global_id.x;

  // Base WGSL omits u64 arithmetic forcing overflow detection across word halves
  let nonce_lo = params.nonce_lo + idx;
  let carry = select(0u, 1u, nonce_lo < params.nonce_lo);
  let nonce_hi = params.nonce_hi + carry;

  var w: array<u32, 64>;
  w[0] = params.key0;
  w[1] = params.key1;
  w[2] = params.key2;
  w[3] = params.key3;
  w[4] = params.key4;
  w[5] = params.key5;
  w[6] = params.key6;
  w[7] = params.key7;
  w[8] = nonce_hi;
  w[9] = nonce_lo;
  w[10] = 0x80000000u;
  w[11] = 0u;
  w[12] = 0u;
  w[13] = 0u;
  w[14] = 0u;
  w[15] = 0x00000140u;

  for (var i = 16u; i < 64u; i = i + 1u) {
    let s0 = rotr(w[i - 15u], 7u) ^ rotr(w[i - 15u], 18u) ^ (w[i - 15u] >> 3u);
    let s1 = rotr(w[i - 2u], 17u) ^ rotr(w[i - 2u], 19u) ^ (w[i - 2u] >> 10u);
    w[i] = w[i - 16u] + s0 + w[i - 7u] + s1;
  }

  var a = 0x6a09e667u;
  var b = 0xbb67ae85u;
  var c = 0x3c6ef372u;
  var d = 0xa54ff53au;
  var e = 0x510e527fu;
  var f = 0x9b05688cu;
  var g = 0x1f83d9abu;
  var h = 0x5be0cd19u;

  for (var i = 0u; i < 64u; i = i + 1u) {
    let s1 = rotr(e, 6u) ^ rotr(e, 11u) ^ rotr(e, 25u);
    let ch = (e & f) ^ (~e & g);
    let t1 = h + s1 + ch + K[i] + w[i];
    let s0 = rotr(a, 2u) ^ rotr(a, 13u) ^ rotr(a, 22u);
    let maj = (a & b) ^ (a & c) ^ (b & c);
    let t2 = s0 + maj;

    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }

  let h0 = 0x6a09e667u + a;

  if (countLeadingZeros(h0) >= params.difficulty) {
    atomicStore(&result.found, 1u);
    atomicMin(&result.nonce_hi, nonce_hi);
    atomicMin(&result.nonce_lo, nonce_lo);
  }
}
`;

export async function createGpuSolver() {
  if (typeof navigator === "undefined" || !navigator.gpu) {
    return null;
  }

  const adapter = await navigator.gpu.requestAdapter();
  if (!adapter) {
    return null;
  }

  let device;
  try {
    device = await adapter.requestDevice();
  } catch {
    return null;
  }
  if (!device) {
    return null;
  }

  const shaderModule = device.createShaderModule({
    code: WGSL_SHADER,
  });

  const bindGroupLayout = device.createBindGroupLayout({
    entries: [
      {
        binding: 0,
        visibility: GPUShaderStage.COMPUTE,
        buffer: { type: "uniform" },
      },
      {
        binding: 1,
        visibility: GPUShaderStage.COMPUTE,
        buffer: { type: "storage" },
      },
    ],
  });

  const pipelineLayout = device.createPipelineLayout({
    bindGroupLayouts: [bindGroupLayout],
  });

  const pipeline = device.createComputePipeline({
    layout: pipelineLayout,
    compute: {
      module: shaderModule,
      entryPoint: "main",
    },
  });

  return {
    async solve(keyBytes, difficulty, onProgress) {
      if (difficulty < 1 || difficulty > 32) {
        throw new RangeError("difficulty must be between 1 and 32");
      }
      if (keyBytes.byteLength !== 32) {
        throw new RangeError("keyBytes must be 32 bytes");
      }

      const keyView = new DataView(
        keyBytes.buffer,
        keyBytes.byteOffset,
        keyBytes.byteLength
      );
      const keyWords = new Uint32Array(8);
      for (let i = 0; i < 8; i++) {
        keyWords[i] = keyView.getUint32(i * 4, false);
      }

      const uniformBuffer = device.createBuffer({
        size: 48,
        usage: GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST,
      });

      const resultBuffer = device.createBuffer({
        size: 16,
        usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC | GPUBufferUsage.COPY_DST,
      });

      const stagingBuffer = device.createBuffer({
        size: 16,
        usage: GPUBufferUsage.MAP_READ | GPUBufferUsage.COPY_DST,
      });

      const bindGroup = device.createBindGroup({
        layout: bindGroupLayout,
        entries: [
          { binding: 0, resource: { buffer: uniformBuffer } },
          { binding: 1, resource: { buffer: resultBuffer } },
        ],
      });

      const batchSize = 65535 * 256;
      const workgroups = batchSize / 256;
      let hashesDone = 0n;
      let nonceStart = 0n;
      let winningNonce = null;

      const uniformData = new Uint32Array(12);
      uniformData.set(keyWords, 0);
      uniformData[10] = difficulty;
      uniformData[11] = 0;

      const initResultData = new Uint32Array([0, 0xffffffff, 0xffffffff, 0]);

      try {
        while (winningNonce === null) {
          const nonceHi = Number((nonceStart >> 32n) & 0xffffffffn);
          const nonceLo = Number(nonceStart & 0xffffffffn);
          uniformData[8] = nonceHi;
          uniformData[9] = nonceLo;

          device.queue.writeBuffer(uniformBuffer, 0, uniformData);
          device.queue.writeBuffer(resultBuffer, 0, initResultData);

          const commandEncoder = device.createCommandEncoder();
          const pass = commandEncoder.beginComputePass();
          pass.setPipeline(pipeline);
          pass.setBindGroup(0, bindGroup);
          pass.dispatchWorkgroups(workgroups, 1, 1);
          pass.end();

          commandEncoder.copyBufferToBuffer(resultBuffer, 0, stagingBuffer, 0, 16);
          device.queue.submit([commandEncoder.finish()]);

          await stagingBuffer.mapAsync(GPUMapMode.READ);
          const readData = new Uint32Array(stagingBuffer.getMappedRange().slice());
          stagingBuffer.unmap();

          hashesDone += BigInt(batchSize);
          if (onProgress) {
            onProgress(hashesDone);
          }

          if (readData[0] !== 0) {
            const foundHi = BigInt(readData[1]);
            const foundLo = BigInt(readData[2]);
            winningNonce = (foundHi << 32n) | foundLo;
          } else {
            nonceStart += BigInt(batchSize);
          }
        }
      } finally {
        uniformBuffer.destroy();
        resultBuffer.destroy();
        stagingBuffer.destroy();
      }

      return winningNonce;
    },
  };
}
