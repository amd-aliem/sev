# CLAUDE.md — virtee/sev demos site (gh-pages branch)

**This branch is a static website, not the Rust crate.** The crate source lives
on `main`. Don't read `src/` to work on the site — everything the site needs is
self-contained here. Only drop to `main`/`src/` if the on-wire format itself
changed upstream and a parser needs updating.

## Branch gotchas (read before `git` anything)

- `gh-pages` is an **orphan** branch — no shared history with `main`.
- The crate's files (`src/`, `Cargo.toml`, `target/`, …) are physically present
  in the working tree (left over from the branch checkout) but are **gitignored
  here** (see `.gitignore`). `git status` stays clean of them. Never `git add -A`
  blind — add specific site paths.
- `README.md` on disk may be the crate's README (restored on branch switch). The
  committed site `README.md` is the one in `git show HEAD:README.md`. Don't
  "fix" the on-disk README thinking it drifted.
- Commit workflow that works: `git add <specific site files>` then commit. Avoid
  chaining `&& git push` after `pkill`/background-server commands — a non-zero
  exit from the cleanup step silently skips the commit. Commit, then push as a
  separate command.
- Commit message footer: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`

## Layout

```
index.html              landing page; renders cards from assets/js/demos.js
assets/css/site.css     shared design system + CSS vars (--bg, --accent, …)
assets/js/demos.js      DEMO REGISTRY — the source of truth for which demos exist
assets/js/layout.js     mountChrome({base}) injects shared header/footer
demos/<id>/             one folder per demo (index.html + its own js/css)
```

Pure static site. No build step, no framework, ES modules only. Everything runs
client-side; nothing is uploaded (say so in UI copy).

## Add a demo (the whole procedure)

1. Append an entry to `assets/js/demos.js` (`status:"soon"` until ready).
2. `demos/<id>/index.html` links `../../assets/css/site.css` + its own css, and
   its module calls `mountChrome({ base: "../../" })`.
3. Flip `status:"live"` — the landing card auto-links. No other wiring.

## Verify without a browser (no browser is installed on this box)

Node can exercise the ES modules directly.

- Syntax check every module you touch: `node --check <file.js>`.
- **attestation-explorer has a checked-in harness: `node demos/attestation-explorer/_verify.mjs`.**
  It does the parser-only logic check *and* the full UI render check (imports
  `explorer.js` against a complete DOM stub, asserts `output.innerHTML`), and
  exits non-zero on failure. Extend its assertions when you touch that demo
  instead of rebuilding a stub.
- Building a stub from scratch for another demo? The two-global shim
  (`atob` + `fetch` below) is enough to import a **parser** module, but importing
  a **UI** module that calls `mountChrome` also needs `document`/`window`, and
  `body.prepend`/`append`. `navigator` is a read-only getter in Node (use
  `Object.defineProperty`, not assignment), and relative imports resolve from the
  stub file's own dir. See `_verify.mjs` for a full, working example to copy.

```js
globalThis.atob = (b64) => Buffer.from(b64, "base64").toString("binary");
globalThis.fetch = async () => ({ text: async () => readFileSync("./sample.b64","utf8") });
```

- Serve for the user to eyeball: `python3 -m http.server 8099`.

**I cannot see the painted page.** Structure/logic I verify programmatically;
visual spacing/color/scroll I cannot. Flag that to the user and let them eyeball.

## Project intent

Grow into a better-looking, hands-on [virtee.io](https://virtee.io) — working,
interactive examples for learning AMD SEV / SEV-SNP. Extensibility first: new
demos should be drop-in via the registry. Eventually the parsing logic is sourced
from the crate compiled to WebAssembly (see `demos/attestation-explorer/CLAUDE.md`).

Live at `https://amd-aliem.github.io/sev/` once Pages is enabled on this branch.
