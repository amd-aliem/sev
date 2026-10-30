// Attestation explorer UI — links a struct map (left) to decoded cards (right).
import { mountChrome } from "../../assets/js/layout.js";
import { decodeInput, parseAttestationReport, layoutForVariant } from "./parser.js";

mountChrome({ base: "../../" });

const input = document.getElementById("report-input");
const out = document.getElementById("output");
const errBox = document.getElementById("error");

// Group metadata: ties a left-pane field's `group` to a right-pane card.
// Order here is the order cards appear on the right.
const GROUP_ORDER = ["identity", "policy", "platform", "key", "tcb", "data", "ids", "mitigation"];
const GROUP_META = {
  identity:   { title: "Identity",                icon: "🆔" },
  policy:     { title: "Guest Policy",            icon: "📜" },
  platform:   { title: "Platform Info",           icon: "🖥️" },
  key:        { title: "Signing Key",             icon: "🔑" },
  tcb:        { title: "TCB Versions",            icon: "🧬" },
  data:       { title: "Measurement & Guest Data",icon: "📐" },
  ids:        { title: "Identifiers & Signature", icon: "🔗" },
  mitigation: { title: "Mitigation Vectors",      icon: "🛡️" },
};

// ---- small render helpers -------------------------------------------------

const esc = (s) => String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
const hx = (n, pad = 3) => "0x" + n.toString(16).toUpperCase().padStart(pad, "0");

function kv(pairs) {
  return `<div class="kv">${pairs
    .map(([k, v]) => `<div>${esc(k)}</div><div>${v}</div>`)
    .join("")}</div>`;
}

function flags(obj, labels) {
  return `<div class="flags">${labels
    .map(([key, label]) => {
      const on = obj[key] === true;
      return `<span class="flag ${on ? "on" : "off"}">${esc(label)} <span class="v">${on ? "✓" : "✗"}</span></span>`;
    })
    .join("")}</div>`;
}

// A hex block tagged with the field it came from, so clicking its offset chip
// can cross-link back to the struct map.
function hexBlock(label, hex, field) {
  const chip = field ? `<span class="off-chip" data-off="${field.off}">${hx(field.off)} · ${field.size}B</span>` : "";
  return `
    <div class="hexblock" ${field ? `data-off="${field.off}"` : ""}>
      <div class="hexblock-head">
        ${label ? `<label class="field-label">${esc(label)}</label>` : ""}
        ${chip}
      </div>
      <div class="hexrow">
        <code class="hex">${esc(hex)}</code>
        <button class="copy" data-copy="${esc(hex)}">copy</button>
      </div>
    </div>`;
}

function tcbField(v) {
  return v === null || v === undefined ? "—" : v;
}

function tcbTable(r) {
  const rows = [
    ["FMC", "fmc"],
    ["Bootloader", "bootloader"],
    ["TEE", "tee"],
    ["SNP", "snp"],
    ["Microcode", "microcode"],
  ];
  const cols = [
    ["Current", r.current_tcb],
    ["Reported", r.reported_tcb],
    ["Committed", r.committed_tcb],
    ["Launch", r.launch_tcb],
  ];
  return `
    <table class="tcb-table">
      <thead><tr><th>Field</th>${cols.map(([c]) => `<th>${c}</th>`).join("")}</tr></thead>
      <tbody>
        ${rows
          .map(
            ([label, key]) =>
              `<tr><td>${label}</td>${cols
                .map(([, tcb]) => `<td>${tcbField(tcb[key])}</td>`)
                .join("")}</tr>`
          )
          .join("")}
        <tr class="build-row"><td>Build (maj.min.bld)</td>
          <td>${esc(r.current_build)}</td><td>—</td>
          <td>${esc(r.committed_build)}</td><td>—</td></tr>
      </tbody>
    </table>`;
}

// ---- per-group card bodies ------------------------------------------------
// `L` is a map from field name -> layout row, so bodies can tag hex blocks.

function cardBody(groupId, r, L) {
  switch (groupId) {
    case "identity":
      return kv([
        ["Version", r.version],
        ["Guest SVN", r.guest_svn],
        ["VMPL", r.vmpl],
        ["Signature algo", esc(r.sig_algo.name)],
        ["Family ID", `<code>${r.family_id}</code>`],
        ["Image ID", `<code>${r.image_id}</code>`],
        r.cpuid
          ? ["CPUID", `family ${hx(r.cpuid.family, 2)}, model ${hx(r.cpuid.model, 2)}, step ${r.cpuid.step}`]
          : ["CPUID", "— (v2 report)"],
      ]);
    case "policy":
      return (
        kv([["ABI version", `${r.policy.abi_major}.${r.policy.abi_minor}`]]) +
        flags(r.policy, [
          ["smt_allowed", "SMT"],
          ["migrate_ma_allowed", "Migrate MA"],
          ["debug_allowed", "Debug"],
          ["single_socket_required", "Single socket"],
          ["cxl_allowed", "CXL"],
          ["mem_aes_256_xts", "AES-256-XTS"],
          ["rapl_dis", "RAPL disabled"],
          ["ciphertext_hiding", "Ciphertext hiding"],
          ["page_swap_disabled", "Page swap disabled"],
        ])
      );
    case "platform":
      return flags(r.plat_info, [
        ["smt_enabled", "SMT"],
        ["tsme_enabled", "TSME"],
        ["ecc_enabled", "ECC"],
        ["rapl_disabled", "RAPL disabled"],
        ["ciphertext_hiding_enabled", "Ciphertext hiding"],
        ["alias_check_complete", "Alias check"],
        ["tio_enabled", "SEV-TIO"],
      ]);
    case "key":
      return kv([
        ["Signing key", `<b>${esc(r.key_info.signing_key)}</b>`],
        ["Author key present", r.key_info.author_key_en ? "yes" : "no"],
        ["Mask chip key", r.key_info.mask_chip_key ? "yes" : "no"],
      ]);
    case "tcb":
      return tcbTable(r);
    case "data":
      return (
        hexBlock("Measurement", r.measurement, L.measurement) +
        hexBlock("Report data", r.report_data, L.report_data) +
        hexBlock("Host data", r.host_data, L.host_data)
      );
    case "ids":
      return (
        hexBlock("Chip ID", r.chip_id, L.chip_id) +
        hexBlock("Report ID", r.report_id, L.report_id) +
        hexBlock("Report ID (MA)", r.report_id_ma, L.report_id_ma) +
        hexBlock("ID key digest", r.id_key_digest, L.id_key_digest) +
        hexBlock("Author key digest", r.author_key_digest, L.author_key_digest) +
        hexBlock("Signature", r.signature, L.signature)
      );
    case "mitigation":
      return kv([
        ["Launch mit. vector", `<code>${esc(r.launch_mit_vector ?? "—")}</code>`],
        ["Current mit. vector", `<code>${esc(r.current_mit_vector ?? "—")}</code>`],
      ]);
    default:
      return "";
  }
}

// Short, human summary shown on the right of a card's header.
function cardSummary(groupId, r) {
  switch (groupId) {
    case "identity":   return `v${r.version} · ${r.meta.generation}`;
    case "policy":     return "0x" + r.policy.raw.toString(16);
    case "platform":   return "0x" + r.plat_info.raw.toString(16);
    case "key":        return r.key_info.signing_key;
    case "tcb":        return r.meta.generation + " layout";
    case "data":       return "SHA-384";
    case "ids":        return "6 fields";
    case "mitigation": return "V5";
    default:           return "";
  }
}

// ---- main render ----------------------------------------------------------

function render(r) {
  const fields = layoutForVariant(r.meta.variant);
  // name -> layout row (skip reserved; last wins is fine, names are unique except _reserved)
  const L = {};
  for (const f of fields) if (f.group) L[f.name] = f;

  // which groups are actually present (so we don't render empty cards)
  const present = new Set(fields.map((f) => f.group).filter(Boolean));
  const groups = GROUP_ORDER.filter((g) => present.has(g));

  // ---- left: struct map ----
  const rows = fields
    .map((f) => {
      const reserved = !f.group;
      const variantTag = f.minVariant ? `<span class="vtag">v${f.minVariant}+</span>` : "";
      return `
        <li class="srow${reserved ? " reserved" : ""}"
            ${reserved ? "" : `data-group="${f.group}"`} data-off="${f.off}">
          <span class="off">${hx(f.off)}</span>
          <span class="sz">${f.size}B</span>
          <span class="fname">${esc(f.name)}${variantTag}</span>
          <span class="ftype">${esc(f.type)}</span>
        </li>`;
    })
    .join("");

  const structMap = `
    <aside class="struct-map">
      <div class="struct-head">
        <code>struct AttestationReport</code>
        <span>${r.meta.byteLength} bytes</span>
      </div>
      <ol class="struct-rows">${rows}</ol>
      <div class="struct-foot">Hover a field to find it · click to open its card</div>
    </aside>`;

  // ---- right: cards ----
  const cards = groups
    .map((g) => {
      const m = GROUP_META[g];
      return `
        <section class="group" data-group="${g}" tabindex="0">
          <div class="group-head">
            <span class="swatch"></span>
            <span class="g-icon">${m.icon}</span>
            <span class="g-title">${esc(m.title)}</span>
            <span class="g-summary">${esc(cardSummary(g, r))}</span>
            <span class="pin-dot" title="Pinned">📌</span>
          </div>
          <div class="group-body">${cardBody(g, r, L)}</div>
        </section>`;
    })
    .join("");

  out.innerHTML = `
    <div class="summary-banner">
      <span class="pill">Report <b>v${r.version}</b></span>
      <span class="pill">Generation <b>${esc(r.meta.generation)}</b></span>
      <span class="pill">Signing key <b>${esc(r.key_info.signing_key)}</b></span>
      <span class="pill">VMPL <b>${r.vmpl}</b></span>
      <span class="pill">${r.meta.byteLength} bytes</span>
    </div>
    <div class="dissect">
      ${structMap}
      <div class="cards">${cards}</div>
    </div>`;

  wireInteractions();
}

// ---- interactions ---------------------------------------------------------

function wireInteractions() {
  const srows = [...out.querySelectorAll(".srow[data-group]")];
  const cards = [...out.querySelectorAll(".group")];
  const cardByGroup = (g) => cards.find((c) => c.dataset.group === g);

  let pinned = null; // the one group whose highlight persists
  let hovered = null;

  // Reflect pin + hover state onto both panes.
  const paint = () => {
    for (const el of [...srows, ...cards]) {
      const g = el.dataset.group;
      el.classList.toggle("pinned", g === pinned);
      el.classList.toggle("hl", g === hovered && g !== pinned);
    }
  };

  const setHover = (g) => { hovered = g; paint(); };

  // Pin a group (one at a time). Re-pinning the same group unpins it.
  // `scrollCard` brings the right-hand card into view (used from the left pane).
  const pin = (g, { scrollCard = false } = {}) => {
    pinned = pinned === g ? null : g;
    paint();
    if (pinned && scrollCard) {
      const card = cardByGroup(pinned);
      if (card) {
        card.scrollIntoView({ behavior: "smooth", block: "center" });
        flash(card);
      }
    }
  };

  // left pane: hover to preview, click to pin + scroll the matching card
  srows.forEach((s) => {
    s.addEventListener("mouseenter", () => setHover(s.dataset.group));
    s.addEventListener("mouseleave", () => setHover(null));
    s.addEventListener("click", () => pin(s.dataset.group, { scrollCard: true }));
  });

  // right pane: hover to preview, click anywhere on the card to pin
  cards.forEach((c) => {
    c.addEventListener("mouseenter", () => setHover(c.dataset.group));
    c.addEventListener("mouseleave", () => setHover(null));
    c.addEventListener("click", (e) => {
      if (e.target.closest(".copy, .off-chip")) return; // those have their own actions
      pin(c.dataset.group);
    });
  });

  // offset chips inside hex blocks jump to the struct row (and pin the group)
  out.querySelectorAll(".off-chip").forEach((chip) => {
    chip.addEventListener("click", (e) => {
      e.stopPropagation();
      const row = srows.find((s) => s.dataset.off === chip.dataset.off);
      if (row) {
        pinned = row.dataset.group;
        paint();
        row.scrollIntoView({ behavior: "smooth", block: "center" });
        flash(row);
      }
    });
  });

  // copy buttons
  out.querySelectorAll(".copy").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      await navigator.clipboard.writeText(btn.dataset.copy);
      btn.textContent = "copied";
      btn.classList.add("done");
      setTimeout(() => {
        btn.textContent = "copy";
        btn.classList.remove("done");
      }, 1200);
    });
  });

  function flash(el) {
    el.classList.remove("flash");
    void el.offsetWidth; // restart animation
    el.classList.add("flash");
  }
}

// ---- events ---------------------------------------------------------------

function run() {
  errBox.textContent = "";
  out.innerHTML = "";
  try {
    const bytes = decodeInput(input.value);
    const report = parseAttestationReport(bytes);
    render(report);
  } catch (e) {
    errBox.textContent = "⚠ " + e.message;
  }
}

document.getElementById("parse-btn").addEventListener("click", run);
document.getElementById("clear-btn").addEventListener("click", () => {
  input.value = "";
  out.innerHTML = "";
  errBox.textContent = "";
});

async function loadSample() {
  const res = await fetch("./sample.b64");
  input.value = (await res.text()).trim();
  run();
}

document.getElementById("sample-btn").addEventListener("click", loadSample);

// Load the sample report by default so visitors see a decoded report immediately.
loadSample();
