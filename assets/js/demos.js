// ===========================================================================
// Demo registry — single source of truth for the showcase.
//
// To add a new demo: append an entry here and create its page under /demos/.
// `status: "live"` makes the card a link; "soon" renders it disabled.
// The landing page and any "other demos" navigation read from this list.
// ===========================================================================

export const DEMOS = [
  {
    id: "attestation-explorer",
    title: "Attestation Report Explorer",
    icon: "🔎",
    href: "demos/attestation-explorer/",
    status: "live",
    blurb:
      "Paste a raw SEV-SNP attestation report (hex or base64) and decode every " +
      "field — policy flags, TCB versions, measurement, and signing key — using " +
      "the same byte layout as the sev crate.",
  },
  {
    id: "cert-chain-explorer",
    title: "Certificate Chain Explorer",
    icon: "🔗",
    href: "demos/cert-chain-explorer/",
    status: "soon",
    blurb:
      "Walk the SEV-SNP trust chain from ARK → ASK → VCEK, inspecting each " +
      "certificate and how it anchors a report's signature.",
  },
  {
    id: "measurement-explorer",
    title: "Measurement Explorer",
    icon: "📐",
    href: "demos/measurement-explorer/",
    status: "soon",
    blurb:
      "Reproduce the launch measurement from an OVMF image and guest config, " +
      "and see what changes when the configuration changes.",
  },
  {
    id: "vm-launch",
    title: "VM Launch Walkthrough",
    icon: "🚀",
    href: "demos/vm-launch/",
    status: "soon",
    blurb:
      "Step through the SEV-SNP guest launch sequence — the ioctls, the session, " +
      "and the handshake that produces an encrypted VM.",
  },
  {
    id: "attack-demos",
    title: "Attack Demos",
    icon: "🛡️",
    href: "demos/attack-demos/",
    status: "soon",
    blurb:
      "Interactive illustrations of what SEV-SNP defends against — and what a " +
      "forged or replayed report looks like when verification is skipped.",
  },
];
