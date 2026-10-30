# CLAUDE.md — Attestation Report Explorer

Decodes a raw SEV-SNP attestation report (1184 / 0x4A0 bytes) entirely in the
browser and links the byte struct (left) to decoded cards (right).

## Files

- `parser.js` — **the only module that knows the wire format.** Exports
  `REPORT_LEN`, `LAYOUT`, `layoutForVariant()`, `decodeInput()`,
  `parseAttestationReport()`. This is the WASM swap point (see bottom).
- `explorer.js` — UI. Renders struct map + cards from the parser, wires
  pin/hover/scroll interactions, and the hover-tooltip engine (`wireTooltips`,
  one bubble appended to `<body>` so cards' `overflow:hidden` can't clip it).
- `descriptions.js` — **human-editable tooltip text**, co-located so non-coders
  can edit it. `DESCRIPTIONS.groups[g]` = card-title tooltip;
  `DESCRIPTIONS.fields[g][key]` = per-field. `key` matches what the UI passes:
  policy/platform flags by bit key (`smt_allowed`), everything else by its
  visible label (`"Guest SVN"`, `"Measurement"`, TCB row/col `"SNP"`/`"Current"`).
  Missing entry = no tooltip. Adding a field? Add its description here too.
- `explorer.css` — demo styling; per-group color via `--g` CSS var keyed off
  `[data-group="…"]`.
- `index.html` — page shell + intro copy.
- `sample.b64` — default report, auto-loaded on page open.
- `_verify.mjs` — headless check: `node _verify.mjs`. Parser asserts + full UI
  render (tooltip count, field text) against a DOM stub. Run after any change
  here; extend its assertions rather than hand-rolling a stub.

## Byte layout — DON'T re-derive from the crate

`parser.js` `LAYOUT[]` is the authoritative field table (offset, size, name,
type, group), transcribed from the crate's `AttestationReport::decode` in
`main:src/firmware/guest/types/snp.rs`. Trust it; only re-check against the crate
if the upstream format version changed. Key facts that cost time to rediscover:

- **Little-endian** scalars. Report is 1184 bytes; signed region is `[0..0x2A0]`.
- **`Version` structs store build, minor, major** (reverse order) — so
  `current_build = "${b[0x1EA]}.${b[0x1E9]}.${b[0x1E8]}"` (major.minor.build).
- **`TcbVersion` layout is generation-dependent** (Milan/Genoa legacy vs Turin
  vs Venice) — byte positions differ. See `parseTcb()`.
- **Generation detection**: V3+ reads CPUID family/model at 0x188/0x189
  (`identifyCpu`); V2 infers Turin-vs-Genoa from the chip-id tail
  (`chipIdGeneration`).
- **Variant/version**: version field 2→V2, 3|4→V3, else V5. CPUID fields are
  V3+, mitigation vectors (0x1F8/0x200) are V5-only. `layoutForVariant()`
  filters by `minVariant` and **synthesizes `_reserved` rows to fill gaps** so
  the map always tiles 0..1184 exactly.
- **Mitigation vectors are decoded structurally, NOT semantically.**
  `parseMitVector()` splits each u64 into its set-bit indices (`.bits`) and
  `parseAttestationReport` computes `mit_diff` (bits in current-but-not-launch =
  applied by a live firmware update after boot). We deliberately do **not** map
  bit N → CVE: AMD states bit meanings are platform- and bug-specific and live
  in Security Bulletins, not the ABI spec. The one public mapping that existed
  (AMD-SB-3023: bit 3 = CVE-2025-48514) was retracted as wrong — so a decode
  table would be both non-portable and actively incorrect. The card
  (`mitBody()` in explorer.js) shows raw hex + bit chips + a launch↔current diff
  banner + a note linking to the bulletins. Sample report has bits {0,3} set.
- **Bitfield helpers** (`bit`/`field`) coerce with `BigInt(v)` because policy &
  platform_info are u64 (BigInt) but key_info is u32 (Number) — don't remove the
  coercion or u32 fields throw "Cannot mix BigInt".

Invariant worth re-asserting after layout edits: every variant tiles exactly.

```js
import { layoutForVariant, REPORT_LEN } from "./parser.js";
for (const v of ["V2","V3","V5"]) {
  let cur=0; for (const f of layoutForVariant(v)) { if(f.off!==cur) throw v+" gap@"+f.name; cur=f.off+f.size; }
  if (cur!==REPORT_LEN) throw v+" ends at "+cur;
}
```

## UI model (so you don't reverse-engineer it)

- Left `.srow[data-group]` ↔ right `.group[data-group]` linked by group id.
  Groups: identity, policy, platform, key, tcb, data, ids, mitigation.
- **One pin at a time.** Click pins a group's highlight; re-click same = unpin;
  click other = move pin. Clicking a left field pins + autoscrolls the card.
  Hover = transient preview that yields to the pin. Offset chips pin + scroll to
  the struct row. (No collapse/expand — that was removed.)
- Adding a field: add its `LAYOUT` row (with a `group`), and make sure that
  group has a `cardBody()` case + `GROUP_META`/`GROUP_ORDER` entry.

## sample.b64

Real V5 Genoa report from
`~/git/amd-aliem/sev-certify/artifacts/3.0/3.0.0-0/attestation_test/report.bin`,
with **chip_id (0x1A0), report_id (0x140), report_data (0x50) overwritten with
`0xABCD…`** placeholders (identity scrub — invalidates the signature, which is
fine and noted in the UI). Measurement/TCB/policy/build are the real values. To
regenerate, re-scrub those three offsets and base64-encode.

## WASM migration (the endgame)

`parser.js` is deliberately the sole format-aware module. Replace it with a shim
that calls a `wasm-bindgen` export over the crate's real `AttestationReport`
parse and returns the **same object shape** (`parseAttestationReport` →
`{ meta, policy, plat_info, key_info, *_tcb, …hex strings }`) plus the same
`LAYOUT`/`layoutForVariant` exports. The UI then needs zero changes.
