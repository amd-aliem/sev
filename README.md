# virtee/sev — Interactive Demos (GitHub Pages)

This branch (`gh-pages`) is a **static website** that showcases the technology in
the [`sev`](https://github.com/virtee/sev) crate through interactive, in-browser
demos. The crate's Rust source lives on `main`.

> Goal: grow this into a better-looking, hands-on version of
> [virtee.io](https://virtee.io) — a place to *learn* AMD SEV / SEV-SNP by
> poking at real data, with working examples for each concept.

## Live demos

| Demo | Status | What it does |
|------|--------|--------------|
| **Attestation Report Explorer** | ✅ live | Decode a raw SEV-SNP attestation report (hex/base64) field by field. |
| Certificate Chain Explorer | 🔜 | Walk ARK → ASK → VCEK. |
| Measurement Explorer | 🔜 | Reproduce a launch measurement. |
| VM Launch Walkthrough | 🔜 | Step through the guest launch sequence. |
| Attack Demos | 🔜 | Illustrate what SEV-SNP defends against. |

## Structure

```
index.html                      Landing page (renders cards from the registry)
assets/
  css/site.css                  Shared design system
  js/demos.js                   Demo registry — THE source of truth for cards
  js/layout.js                  Shared header/footer
demos/
  attestation-explorer/
    index.html                  Demo page
    explorer.js                 UI wiring
    explorer.css                Demo-specific styles
    parser.js                   Report byte-layout parser (the swap point for wasm)
    sample.b64                  A valid sample report
```

## Adding a demo

1. Append an entry to `assets/js/demos.js` (set `status: "soon"` until it's ready).
2. Create `demos/<your-demo>/` with its own `index.html`, mounting the shared
   chrome via `mountChrome({ base: "../../" })`.
3. Flip the entry to `status: "live"` — the landing card links automatically.

## The WebAssembly plan

`demos/attestation-explorer/parser.js` is deliberately the **only** module that
knows the report wire format. It mirrors `AttestationReport::decode` from the
crate. When the crate is compiled to wasm (`wasm-bindgen`), this file becomes a
thin shim that calls the wasm export and returns the same object shape — so the
UI never has to change, and the parsing logic is sourced from the crate itself.

## Local preview

```sh
python3 -m http.server 8099
# open http://localhost:8099/
```

Everything runs client-side. No data is uploaded.
