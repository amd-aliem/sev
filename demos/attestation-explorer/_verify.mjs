// ===========================================================================
// Headless verification harness for the attestation explorer.
//
// No browser is installed on this box, so this exercises the ES modules under
// Node by shimming the handful of browser globals the parser + UI touch. Run:
//
//   node _verify.mjs
//
// It does two layers of check:
//   1. parser-only  — decode sample.b64, assert a few decoded field values.
//   2. full UI      — import explorer.js (which calls mountChrome + renders the
//                     cards) against a stubbed DOM, then assert the rendered
//                     output.innerHTML (e.g. tooltip count, specific strings).
//
// Exits non-zero if any assertion fails, so it doubles as a smoke test.
//
// WHY THIS FILE EXISTS: reconstructing the DOM stub from scratch is fiddly —
// mountChrome needs body.prepend/append, `navigator` is a read-only getter in
// Node, and relative imports resolve from THIS file's dir. Those gotchas are
// baked in here so future sessions don't re-derive them. Extend the assertions
// when you add a card or field; keep the stub generic.
// ===========================================================================

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

const DIR = dirname(fileURLToPath(import.meta.url)) + "/";

let failures = 0;
function assert(cond, msg) {
  if (cond) { console.log("  ✓ " + msg); }
  else { console.log("  ✗ " + msg); failures++; }
}

// ---- browser global shims -------------------------------------------------

globalThis.atob = (b64) => Buffer.from(b64, "base64").toString("binary");

const sample = readFileSync(DIR + "sample.b64", "utf8");
globalThis.fetch = async () => ({ text: async () => sample });

// Minimal fake element. innerHTML is stored verbatim; querySelectorAll only
// understands "[data-tip]" (counts occurrences in the last-set innerHTML),
// which is all wireInteractions/wireTooltips need to not throw at import.
function makeEl(tag = "div") {
  return {
    tagName: tag, value: "", _html: "", textContent: "", className: "",
    style: {}, dataset: {}, children: [],
    classList: {
      _s: new Set(),
      add(c) { this._s.add(c); }, remove(c) { this._s.delete(c); },
      toggle(c, f) { f ? this._s.add(c) : this._s.delete(c); },
      contains(c) { return this._s.has(c); },
    },
    addEventListener() {}, removeEventListener() {},
    setAttribute(k, v) { if (k === "data-tip") this.dataset.tip = v; },
    getAttribute() { return null; }, hasAttribute() { return false; },
    appendChild(c) { this.children.push(c); return c; },
    prepend() {}, append() {}, remove() {}, insertBefore(c) { return c; },
    getBoundingClientRect() { return { top: 10, left: 10, bottom: 30, right: 60, width: 50, height: 20 }; },
    closest() { return null; }, focus() {}, scrollIntoView() {},
    get innerHTML() { return this._html; },
    set innerHTML(v) { this._html = v; },
    querySelector() { return null; },
    querySelectorAll(sel) {
      if (sel === "[data-tip]") {
        const n = (this._html.match(/data-tip=/g) || []).length;
        return Array.from({ length: n }, () => makeEl());
      }
      return [];
    },
  };
}

const store = {};
globalThis.document = {
  getElementById(id) { return (store[id] ||= makeEl()); },
  createElement(t) { return makeEl(t); },
  body: makeEl("body"),
  querySelectorAll() { return []; },
  addEventListener() {},
};
globalThis.window = { addEventListener() {}, innerWidth: 1200, innerHeight: 800 };
// `navigator` is a read-only getter in Node — defineProperty, not assignment.
Object.defineProperty(globalThis, "navigator", {
  value: { clipboard: { writeText: async () => {} } },
  configurable: true,
});

// ---- 1. parser-only checks ------------------------------------------------

console.log("parser:");
const { decodeInput, parseAttestationReport, layoutForVariant, REPORT_LEN } =
  await import(DIR + "parser.js");

const bytes = decodeInput(sample.trim());
const r = parseAttestationReport(bytes);
assert(r.meta.variant === "V5", `variant is V5 (got ${r.meta.variant})`);
assert(r.meta.generation === "Genoa", `generation is Genoa (got ${r.meta.generation})`);
assert(r.key_info.signing_key === "VCEK", `signing key is VCEK (got ${r.key_info.signing_key})`);

// ID block fields are grouped under "idblock" (not identity/ids) in LAYOUT.
const byName = Object.fromEntries(layoutForVariant("V5").map((f) => [f.name, f]));
for (const n of ["guest_svn", "family_id", "image_id", "id_key_digest", "author_key_digest"])
  assert(byName[n]?.group === "idblock", `${n} grouped under idblock (got ${byName[n]?.group})`);

// Mitigation vectors (V5): structural decode into set-bit indices + diff.
assert(r.launch_mit?.hex === "0x9", `launch mit hex 0x9 (got ${r.launch_mit?.hex})`);
assert(JSON.stringify(r.launch_mit?.bits) === "[0,3]", `launch mit bits [0,3] (got ${JSON.stringify(r.launch_mit?.bits)})`);
assert(JSON.stringify(r.current_mit?.bits) === "[0,3]", `current mit bits [0,3] (got ${JSON.stringify(r.current_mit?.bits)})`);
assert(r.mit_diff?.added.length === 0 && r.mit_diff?.removed.length === 0, "sample has no launch↔current mit diff");

// Synthetic live-patch case: flip on bit 5 in current_mit_vector (0x200) and
// confirm the diff flags it as added (applied after launch).
const patched = Uint8Array.from(bytes);
patched[0x200] |= 1 << 5;               // current gains bit 5, launch unchanged
const rp = parseAttestationReport(patched);
assert(JSON.stringify(rp.mit_diff.added) === "[5]", `synthetic: bit 5 flagged as added (got ${JSON.stringify(rp.mit_diff.added)})`);
assert(rp.mit_diff.removed.length === 0, "synthetic: nothing spuriously removed");

// Invariant from parser.js: every variant tiles 0..REPORT_LEN with no gaps.
for (const v of ["V2", "V3", "V5"]) {
  let cur = 0, ok = true;
  for (const f of layoutForVariant(v)) { if (f.off !== cur) { ok = false; break; } cur = f.off + f.size; }
  assert(ok && cur === REPORT_LEN, `${v} layout tiles exactly to ${REPORT_LEN}`);
}

// ---- 2. full UI render checks ---------------------------------------------

console.log("ui:");
await import(DIR + "explorer.js"); // runs mountChrome + loadSample()
await new Promise((res) => setTimeout(res, 50)); // loadSample() is async

const html = store["output"].innerHTML;
const tipCount = (html.match(/data-tip=/g) || []).length;
assert(html.length > 1000, `output rendered (${html.length} bytes)`);
assert(tipCount >= 40, `tooltips present on fields (${tipCount} data-tip attrs)`);
assert(html.includes('data-group="policy"'), "policy card rendered");
assert(html.includes("Debugging is permitted"), "policy debug tooltip text present");
assert(html.includes("cryptographic fingerprint"), "measurement tooltip text present");

// ID Block & Auth card: sub-section heads + "unused" notice for the sample.
assert(html.includes('data-group="idblock"'), "ID block card rendered");
assert(html.includes("From ID block"), "ID block sub-head rendered");
assert(html.includes("From ID auth"), "ID auth sub-head rendered");
assert(html.includes("No ID block was supplied"), "unused-ID-block notice shown for sample");
assert(html.includes("sets in the ID block to group"), "family-id idblock tooltip present");
// Guest SVN / Family ID moved out of the identity card into idblock.
const identityCard = html.slice(html.indexOf('data-group="identity"'), html.indexOf('data-group="policy"'));
assert(!identityCard.includes("Family ID"), "Family ID no longer in identity card");

// Mitigation card: bit chips + "no diff" banner + security-bulletin note.
assert(html.includes('data-group="mitigation"'), "mitigation card rendered");
assert(html.includes('class="mit-bit"') || html.includes("mit-bit"), "mit bit chips rendered");
assert(html.includes(">bit 3<"), "mit bit 3 chip present");
assert(html.includes("no mitigation changed"), "no-diff banner rendered for sample");
assert(html.includes("AMD Security Bulletins"), "security-bulletin note present");

// ---- result ---------------------------------------------------------------

console.log(failures === 0 ? "\nALL CHECKS PASSED" : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);
