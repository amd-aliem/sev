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

// ---- struct layout --------------------------------------------------------
//
// The on-wire struct, in declaration order, mirroring AttestationReport in
// src/firmware/guest/types/snp.rs. This is the single source of truth for the
// left-hand "struct map": each row is one field with its byte offset, size,
// C-ish type, and the `group` it feeds on the right (so the two panes link).
//
// `minVariant` marks fields that only exist in later report versions:
//   2 = all reports, 3 = V3+, 5 = V5 only.
export const LAYOUT = [
  { off: 0x000, size: 4,   name: "version",           type: "u32",       group: "identity" },
  { off: 0x004, size: 4,   name: "guest_svn",         type: "u32",       group: "identity" },
  { off: 0x008, size: 8,   name: "policy",            type: "u64",       group: "policy" },
  { off: 0x010, size: 16,  name: "family_id",         type: "u8[16]",    group: "identity" },
  { off: 0x020, size: 16,  name: "image_id",          type: "u8[16]",    group: "identity" },
  { off: 0x030, size: 4,   name: "vmpl",              type: "u32",       group: "identity" },
  { off: 0x034, size: 4,   name: "signature_algo",    type: "u32",       group: "identity" },
  { off: 0x038, size: 8,   name: "current_tcb",       type: "TcbVersion",group: "tcb" },
  { off: 0x040, size: 8,   name: "platform_info",     type: "u64",       group: "platform" },
  { off: 0x048, size: 4,   name: "key_info",          type: "u32",       group: "key" },
  { off: 0x050, size: 64,  name: "report_data",       type: "u8[64]",    group: "data" },
  { off: 0x090, size: 48,  name: "measurement",       type: "u8[48]",    group: "data" },
  { off: 0x0c0, size: 32,  name: "host_data",         type: "u8[32]",    group: "data" },
  { off: 0x0e0, size: 48,  name: "id_key_digest",     type: "u8[48]",    group: "ids" },
  { off: 0x110, size: 48,  name: "author_key_digest", type: "u8[48]",    group: "ids" },
  { off: 0x140, size: 32,  name: "report_id",         type: "u8[32]",    group: "ids" },
  { off: 0x160, size: 32,  name: "report_id_ma",      type: "u8[32]",    group: "ids" },
  { off: 0x180, size: 8,   name: "reported_tcb",      type: "TcbVersion",group: "tcb" },
  { off: 0x188, size: 1,   name: "cpuid_fam_id",      type: "u8",        group: "identity", minVariant: 3 },
  { off: 0x189, size: 1,   name: "cpuid_mod_id",      type: "u8",        group: "identity", minVariant: 3 },
  { off: 0x18a, size: 1,   name: "cpuid_step",        type: "u8",        group: "identity", minVariant: 3 },
  { off: 0x1a0, size: 64,  name: "chip_id",           type: "u8[64]",    group: "ids" },
  { off: 0x1e0, size: 8,   name: "committed_tcb",     type: "TcbVersion",group: "tcb" },
  { off: 0x1e8, size: 4,   name: "current_build",     type: "Version",   group: "tcb" },
  { off: 0x1ec, size: 4,   name: "committed_build",   type: "Version",   group: "tcb" },
  { off: 0x1f0, size: 8,   name: "launch_tcb",        type: "TcbVersion",group: "tcb" },
  { off: 0x1f8, size: 8,   name: "launch_mit_vector", type: "u64",       group: "mitigation", minVariant: 5 },
  { off: 0x200, size: 8,   name: "current_mit_vector",type: "u64",       group: "mitigation", minVariant: 5 },
  { off: 0x2a0, size: 512, name: "signature",         type: "Signature", group: "ids" },
];

/**
 * Rows of LAYOUT present for a given variant ("V2"|"V3"|"V5"), with reserved
 * padding synthesized to fill any gaps. The result always tiles 0..REPORT_LEN
 * exactly, so the struct map is a faithful, gap-free picture of the bytes.
 */
export function layoutForVariant(variant) {
  const max = variant === "V2" ? 2 : variant === "V3" ? 3 : 5;
  const present = LAYOUT.filter((f) => (f.minVariant ?? 2) <= max).sort((a, b) => a.off - b.off);

  const out = [];
  let cur = 0;
  for (const f of present) {
    if (f.off > cur) {
      const size = f.off - cur;
      out.push({ off: cur, size, name: "_reserved", type: `u8[${size}]`, group: null });
    }
    out.push(f);
    cur = f.off + f.size;
  }
  if (cur < REPORT_LEN) {
    const size = REPORT_LEN - cur;
    out.push({ off: cur, size, name: "_reserved", type: `u8[${size}]`, group: null });
  }
  return out;
}

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

// Mitigation vectors (V5) are 64-bit bit vectors of firmware vulnerability
// mitigations. Each set bit is one mitigation; the MEANING of a bit is
// platform- and bug-specific and published in AMD Security Bulletins, NOT in
// the ABI spec — so we decode structure (which bits are set) but deliberately
// do NOT map bits to CVEs. See demo CLAUDE.md.
function parseMitVector(v) {
  const bits = [];
  for (let i = 0; i < 64; i++) if ((v >> BigInt(i)) & 1n) bits.push(i);
  return { raw: v, hex: "0x" + v.toString(16), bits };
}

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
    const launch = parseMitVector(u64(b, 0x1f8));
    const current = parseMitVector(u64(b, 0x200));
    report.launch_mit = launch;
    report.current_mit = current;
    // Backwards-compatible hex strings (kept for any existing consumer).
    report.launch_mit_vector = launch.hex;
    report.current_mit_vector = current.hex;
    // Bits set now but NOT at launch = applied by a live firmware update after
    // this guest booted. Bits set at launch but not now = unexpected regression.
    const setL = new Set(launch.bits), setC = new Set(current.bits);
    report.mit_diff = {
      added: current.bits.filter((i) => !setL.has(i)),   // live-patched since launch
      removed: launch.bits.filter((i) => !setC.has(i)),  // present at launch, gone now
    };
  }

  return report;
}
