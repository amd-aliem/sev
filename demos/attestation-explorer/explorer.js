// Attestation explorer UI — wires the textarea to parser.js and renders groups.
import { mountChrome } from "../../assets/js/layout.js";
import { decodeInput, parseAttestationReport } from "./parser.js";

mountChrome({ base: "../../" });

const input = document.getElementById("report-input");
const out = document.getElementById("output");
const errBox = document.getElementById("error");

// ---- small render helpers -------------------------------------------------

const esc = (s) => String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));

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

function hexBlock(label, hex) {
  return `
    <div class="hexblock">
      ${label ? `<label class="field-label">${esc(label)}</label>` : ""}
      <div class="hexrow">
        <code class="hex">${esc(hex)}</code>
        <button class="copy" data-copy="${esc(hex)}">copy</button>
      </div>
    </div>`;
}

function group(title, badge, body, spanAll = false) {
  return `
    <section class="group${spanAll ? " span-all" : ""}">
      <h3>${esc(title)}${badge ? `<span class="badge">${esc(badge)}</span>` : ""}</h3>
      ${body}
    </section>`;
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
      </tbody>
    </table>`;
}

// ---- main render ----------------------------------------------------------

function render(r) {
  const parts = [];

  // summary banner
  parts.push(`
    <div class="summary-banner">
      <span class="pill">Report <b>v${r.version}</b></span>
      <span class="pill">Generation <b>${esc(r.meta.generation)}</b></span>
      <span class="pill">Signing key <b>${esc(r.key_info.signing_key)}</b></span>
      <span class="pill">VMPL <b>${r.vmpl}</b></span>
      <span class="pill">${r.meta.byteLength} bytes</span>
    </div>`);

  parts.push('<div class="result-groups">');

  // Identity
  parts.push(
    group(
      "Identity",
      null,
      kv([
        ["Version", r.version],
        ["Guest SVN", r.guest_svn],
        ["VMPL", r.vmpl],
        ["Signature algo", `${esc(r.sig_algo.name)}`],
        ["Family ID", `<code>${r.family_id}</code>`],
        ["Image ID", `<code>${r.image_id}</code>`],
        r.cpuid
          ? ["CPUID", `family 0x${r.cpuid.family.toString(16)}, model 0x${r.cpuid.model.toString(16)}, step ${r.cpuid.step}`]
          : ["CPUID", "— (v2 report)"],
      ])
    )
  );

  // Guest Policy
  parts.push(
    group(
      "Guest Policy",
      "0x" + r.policy.raw.toString(16),
      kv([
        ["ABI version", `${r.policy.abi_major}.${r.policy.abi_minor}`],
      ]) +
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
    )
  );

  // Platform Info
  parts.push(
    group(
      "Platform Info",
      "0x" + r.plat_info.raw.toString(16),
      flags(r.plat_info, [
        ["smt_enabled", "SMT"],
        ["tsme_enabled", "TSME"],
        ["ecc_enabled", "ECC"],
        ["rapl_disabled", "RAPL disabled"],
        ["ciphertext_hiding_enabled", "Ciphertext hiding"],
        ["alias_check_complete", "Alias check"],
        ["tio_enabled", "SEV-TIO"],
      ])
    )
  );

  // Key Info
  parts.push(
    group(
      "Signing Key",
      "0x" + r.key_info.raw.toString(16),
      kv([
        ["Signing key", `<b>${esc(r.key_info.signing_key)}</b>`],
        ["Author key present", r.key_info.author_key_en ? "yes" : "no"],
        ["Mask chip key", r.key_info.mask_chip_key ? "yes" : "no"],
      ])
    )
  );

  // TCB (spans full width)
  parts.push(group("TCB Versions", esc(r.meta.generation) + " layout", tcbTable(r), true));

  // Measurement & guest data
  parts.push(
    group(
      "Measurement & Guest Data",
      "SHA-384",
      hexBlock("Measurement (48 bytes)", r.measurement) +
        hexBlock("Report data (64 bytes)", r.report_data) +
        hexBlock("Host data (32 bytes)", r.host_data),
      true
    )
  );

  // Identifiers & signature
  parts.push(
    group(
      "Identifiers & Signature",
      null,
      hexBlock("Chip ID (64 bytes)", r.chip_id) +
        hexBlock("Report ID (32 bytes)", r.report_id) +
        hexBlock("ID key digest (48 bytes)", r.id_key_digest) +
        hexBlock("Author key digest (48 bytes)", r.author_key_digest) +
        hexBlock("Signature (512 bytes)", r.signature),
      true
    )
  );

  parts.push("</div>");
  out.innerHTML = parts.join("");

  // wire copy buttons
  out.querySelectorAll(".copy").forEach((btn) => {
    btn.addEventListener("click", async () => {
      await navigator.clipboard.writeText(btn.dataset.copy);
      btn.textContent = "copied";
      btn.classList.add("done");
      setTimeout(() => {
        btn.textContent = "copy";
        btn.classList.remove("done");
      }, 1200);
    });
  });
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
