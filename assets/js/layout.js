// ===========================================================================
// Shared chrome — header and footer injected on every page so the look stays
// consistent as demos are added. `base` is the relative path back to site root
// ("" on the landing page, "../../" inside a demo).
// ===========================================================================

export function mountChrome({ base = "" } = {}) {
  const header = document.createElement("header");
  header.className = "site-header";
  header.innerHTML = `
    <div class="inner">
      <a class="brand" href="${base}index.html">
        virtee<span style="color:var(--text-mut)">/</span>sev
        <span class="chip">demos</span>
      </a>
      <nav>
        <a href="${base}index.html#demos">Demos</a>
        <a href="https://github.com/virtee/sev">GitHub</a>
        <a href="https://docs.rs/sev">docs.rs</a>
        <a href="https://virtee.io">virtee.io</a>
      </nav>
    </div>`;
  document.body.prepend(header);

  const footer = document.createElement("footer");
  footer.className = "site-footer";
  footer.innerHTML = `
    <div class="inner">
      <span>An interactive showcase for the
        <a href="https://github.com/virtee/sev"><code>sev</code></a> crate —
        AMD SEV / SEV-SNP in Rust.</span>
      <span>Decoding runs entirely in your browser. Nothing is uploaded.</span>
    </div>`;
  document.body.append(footer);
}
