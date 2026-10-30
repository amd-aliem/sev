// ===========================================================================
// SEV-SNP attestation report parser (pure JS).
//
// This mirrors the byte layout decoded by the `sev` crate in
//   src/firmware/guest/types/snp.rs  (AttestationReport::decode)
//   src/firmware/host/types/snp.rs   (TcbVersion per generation)
//   src/lib.rs                        (Generation::identify_cpu)
//
// It is intentionally the ONLY module that knows the wire format. When the
// crate is compiled to WebAssembly, this file can be replaced by a thin shim
// that calls the wasm export and returns the same shape — the UI won't change.
//
// Report is 1184 (0x4A0) bytes, little-endian scalars.
// ===========================================================================

export const REPORT_LEN = 1184;

// ---- input decoding -------------------------------------------------------

/** Accept hex (with optional 0x / whitespace / colons) or base64; return Uint8Array. */
export function decodeInput(raw) {
  const s = raw.trim();
  if (!s) throw new Error("Input is empty.");

  // Looks like hex? (only hex chars + separators)
  const hexish = s.replace(/0x/gi, "").replace(/[\s:,]/g, "");
  if (/^[0-9a-fA-F]+$/.test(hexish) && hexish.length % 2 === 0 && hexish.length >= REPORT_LEN) {
    return hexToBytes(hexish);
  }

  // Otherwise try base64 (also tolerate base64url).
  try {
    return base64ToBytes(s.replace(/\s/g, ""));
  } catch {
    // Fall back to hex if it was short-but-hex, to give a better error below.
    if (/^[0-9a-fA-F]+$/.test(hexish)) return hexToBytes(hexish);
    throw new Error("Could not parse input as hex or base64.");
  }
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function base64ToBytes(b64) {
  const norm = b64.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(norm);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ---- little byte cursor ---------------------------------------------------

function u32(b, o) { return b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24) >>> 0; }
function u64(b, o) {
  // BigInt to stay exact for the 64-bit policy/platform fields.
  let v = 0n;
  for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(b[o + i]);
  return v;
}
function slice(b, o, n) { return b.slice(o, o + n); }
function bytesToHex(arr) { return Array.from(arr, (x) => x.toString(16).padStart(2, "0")).join(""); }

// ---- generation detection (mirrors Generation::identify_cpu) --------------

function identifyCpu(family, model) {
  if (family === 0x19) {
    if (model <= 0x0f) return "Milan";
    if ((model >= 0x10 && model <= 0x1f) || (model >= 0xa0 && model <= 0xaf)) return "Genoa";
  } else if (family === 0x1a) {
    if (model <= 0x11) return "Turin";
    if (
      (model >= 0x50 && model <= 0x57) ||
      (model >= 0x90 && model <= 0x9f) ||
      (model >= 0xa0 && model <= 0xaf) ||
      (model >= 0xc0 && model <= 0xc7)
    )
      return "Venice";
  }
  return "Unknown";
}

// For V2 reports (no CPUID fields), the crate infers Turin-vs-Genoa from the chip id.
function chipIdGeneration(chipId) {
  const allZero = chipId.every((x) => x === 0);
  if (allZero) return "Genoa"; // masked chip id — crate errors; we fall back to legacy layout
  const tailZero = chipId.slice(8).every((x) => x === 0);
  return tailZero ? "Turin" : "Genoa";
}

// ---- TcbVersion per generation (mirrors host/types/snp.rs) -----------------

function parseTcb(b, o, generation) {
  const t = slice(b, o, 8);
  switch (generation) {
    case "Milan":
    case "Genoa":
      return { bootloader: t[0], tee: t[1], snp: t[6], microcode: t[7], fmc: null };
    case "Turin":
      return { fmc: t[0], bootloader: t[1], tee: t[2], snp: t[3], microcode: t[7] };
    case "Venice":
      return { fmc: t[0], tee: t[1], snp: t[2], bootloader: null, microcode: null };
    default: // Unknown -> show raw, assume legacy field positions
      return { bootloader: t[0], tee: t[1], snp: t[6], microcode: t[7], fmc: null, raw: bytesToHex(t) };
  }
}

// ---- bitfields ------------------------------------------------------------

// `v` may be a Number (u32 fields) or BigInt (u64 fields); coerce to BigInt.
function bit(v, n) { return (BigInt(v) >> BigInt(n)) & 1n ? true : false; }
function field(v, hi, lo) {
  const mask = (1n << BigInt(hi - lo + 1)) - 1n;
  return Number((BigInt(v) >> BigInt(lo)) & mask);
}

function parsePolicy(v) {
  return {
    raw: v,
    abi_minor: field(v, 7, 0),
    abi_major: field(v, 15, 8),
    smt_allowed: bit(v, 16),
    migrate_ma_allowed: bit(v, 18),
    debug_allowed: bit(v, 19),
    single_socket_required: bit(v, 20),
    cxl_allowed: bit(v, 21),
    mem_aes_256_xts: bit(v, 22),
    rapl_dis: bit(v, 23),
    ciphertext_hiding: bit(v, 24),
    page_swap_disabled: bit(v, 25),
  };
}

function parsePlatformInfo(v) {
  return {
    raw: v,
    smt_enabled: bit(v, 0),
    tsme_enabled: bit(v, 1),
    ecc_enabled: bit(v, 2),
    rapl_disabled: bit(v, 3),
    ciphertext_hiding_enabled: bit(v, 4),
    alias_check_complete: bit(v, 5),
    tio_enabled: bit(v, 7),
  };
}

const SIGNING_KEY = { 0: "VCEK", 1: "VLEK", 7: "None" };
function parseKeyInfo(v) {
  const sk = field(v, 4, 2);
  return {
    raw: v,
    author_key_en: bit(v, 0),
    mask_chip_key: bit(v, 1),
    signing_key: SIGNING_KEY[sk] ?? `Reserved (${sk})`,
  };
}

const SIG_ALGO = { 0: "Invalid", 1: "ECDSA P-384 with SHA-384" };

// ---- main entry point -----------------------------------------------------

export function parseAttestationReport(bytes) {
  if (bytes.length < REPORT_LEN) {
    throw new Error(
      `Report is ${bytes.length} bytes; expected at least ${REPORT_LEN} (0x4A0).`
    );
  }
  const b = bytes;

  const version = u32(b, 0x00);
  const variant = version === 2 ? "V2" : version === 3 || version === 4 ? "V3" : "V5";

  // CPUID fields exist only in V3+. Detect generation accordingly.
  const chipId = slice(b, 0x1a0, 64);
  let generation, cpuid;
  if (variant === "V2") {
    generation = chipIdGeneration(chipId);
    cpuid = null;
  } else {
    const family = b[0x188];
    const model = b[0x189];
    const step = b[0x18a];
    generation = identifyCpu(family, model);
    cpuid = { family, model, step };
  }

  const report = {
    meta: { version, variant, generation, byteLength: bytes.length },
    version,
    guest_svn: u32(b, 0x04),
    policy: parsePolicy(u64(b, 0x08)),
    family_id: bytesToHex(slice(b, 0x10, 16)),
    image_id: bytesToHex(slice(b, 0x20, 16)),
    vmpl: u32(b, 0x30),
    sig_algo: { raw: u32(b, 0x34), name: SIG_ALGO[u32(b, 0x34)] ?? "Unknown" },
    current_tcb: parseTcb(b, 0x38, generation),
    plat_info: parsePlatformInfo(u64(b, 0x40)),
    key_info: parseKeyInfo(u32(b, 0x48)),
    report_data: bytesToHex(slice(b, 0x50, 64)),
    measurement: bytesToHex(slice(b, 0x90, 48)),
    host_data: bytesToHex(slice(b, 0xc0, 32)),
    id_key_digest: bytesToHex(slice(b, 0xe0, 48)),
    author_key_digest: bytesToHex(slice(b, 0x110, 48)),
    report_id: bytesToHex(slice(b, 0x140, 32)),
    report_id_ma: bytesToHex(slice(b, 0x160, 32)),
    reported_tcb: parseTcb(b, 0x180, generation),
    cpuid,
    chip_id: bytesToHex(chipId),
    committed_tcb: parseTcb(b, 0x1e0, generation),
    // Version structs are stored build, minor, major (see Version::decode).
    current_build: `${b[0x1ea]}.${b[0x1e9]}.${b[0x1e8]}`,
    committed_build: `${b[0x1ee]}.${b[0x1ed]}.${b[0x1ec]}`,
    launch_tcb: parseTcb(b, 0x1f0, generation),
    signature: bytesToHex(slice(b, 0x2a0, 512)),
  };

  // V5 adds launch/current mitigation vectors at 0x1F8..0x208.
  if (variant === "V5") {
    report.launch_mit_vector = "0x" + u64(b, 0x1f8).toString(16);
    report.current_mit_vector = "0x" + u64(b, 0x200).toString(16);
  }

  return report;
}
