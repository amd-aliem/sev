// ===========================================================================
// Hover descriptions for the attestation report cards.  HUMAN-EDITABLE.
//
// This file holds the plain-English text that pops up when you hover a field
// (or a card title) in the right-hand pane. Edit the strings freely — no build
// step, no other wiring. Keep them short (a sentence or two); long lines wrap.
//
// Structure:
//   groups[<groupId>]      → tooltip for the whole card (shown on its title)
//   fields[<groupId>][key] → tooltip for one field inside that card
//
// The `key` must match what explorer.js passes for that field:
//   • policy / platform flags → the bit's key   (e.g. "smt_allowed")
//   • key/value & hex rows    → the row's label  (e.g. "Guest SVN", "Measurement")
//   • TCB table               → the row label ("SNP") or column header ("Current")
//
// A missing entry simply means "no tooltip" — safe to leave blank.
// ===========================================================================

export const DESCRIPTIONS = {
  // ---- whole-card summaries (hover the card title) ------------------------
  groups: {
    identity:
      "Who this guest is and which report format the firmware produced.",
    policy:
      "Launch rules the guest owner required — what the hypervisor is and isn't allowed to do to this VM. Enforced by firmware at launch.",
    platform:
      "Hardware and firmware features that were enabled on the host when the report was generated.",
    key:
      "Which key signed this report, and how that key is derived.",
    tcb:
      "Trusted Computing Base: security version numbers for each layer of the firmware stack, compared across four points in time.",
    data:
      "The launch measurement (a fingerprint of what booted) plus data supplied by the guest and host at launch.",
    idblock:
      "Guest-owner identity supplied at launch. The ID block (guest SVN, family/image IDs) is checked by firmware against the measurement and policy; the ID auth struct signs that block and its key digests are bound into every report. All zero = no ID block was used.",
    ids:
      "Unique identifiers for the chip and guest, and the report's cryptographic signature.",
    mitigation:
      "Bit vectors of firmware vulnerability mitigations, at launch vs. now (V5 only). Having both lets a guest detect a mitigation a live firmware update applied after it booted. Each bit's meaning is bug- and platform-specific (AMD Security Bulletins, not the ABI spec), so these are informational — firmware doesn't enforce them and neither should a verifier.",
  },

  // ---- per-field descriptions, grouped by card ----------------------------
  fields: {
    identity: {
      "Version": "Attestation report format version. 2, 3/4, and 5 add progressively more fields.",
      "VMPL": "VM Permission Level the report was requested at. 0 is the most privileged level inside the guest.",
      "Signature algo": "Algorithm used to sign the report. Today this is ECDSA on curve P-384 with SHA-384.",
      "CPUID": "CPU family / model / stepping that produced the report (present in V3+). Used to tell Milan / Genoa / Turin / Venice apart.",
    },

    idblock: {
      "Guest SVN": "Security Version Number of the guest image from the ID block — a monotonic counter the owner bumps to invalidate older, vulnerable images.",
      "Family ID": "16-byte identifier the guest owner sets in the ID block to group related guests. Not interpreted by firmware.",
      "Image ID": "16-byte identifier the guest owner sets in the ID block to name this specific image. Not interpreted by firmware.",
      "ID key digest": "SHA-384 of the public ID key that signed the ID block. Firmware records it so a verifier can confirm which key vouched for this guest's identity.",
      "Author key digest": "SHA-384 of the author key that signed the ID key, if one was used (all zero otherwise). Lets one author key certify many ID keys.",
    },

    policy: {
      "ABI version": "Minimum SEV-SNP firmware ABI (major.minor) required to launch this guest. The host must run at least this firmware.",
      smt_allowed: "Simultaneous Multi-Threading may be enabled on the host. Disallowing it closes some cross-thread side channels.",
      migrate_ma_allowed: "The guest may be migrated to another machine using a Migration Agent.",
      debug_allowed: "Debugging is permitted — this lets the host decrypt and inspect guest memory. Normally OFF in production.",
      single_socket_required: "The guest must run on a single CPU socket.",
      cxl_allowed: "CXL-attached memory is allowed to be used by the guest.",
      mem_aes_256_xts: "Require AES-256-XTS for memory encryption rather than the 128-bit mode.",
      rapl_dis: "RAPL power reporting must be disabled — mitigates power-analysis side channels.",
      ciphertext_hiding: "Ciphertext hiding must be enabled, preventing the host from reading raw encrypted DRAM.",
      page_swap_disabled: "The host is not allowed to swap this guest's pages out to disk.",
    },

    platform: {
      smt_enabled: "Simultaneous Multi-Threading is enabled on this platform.",
      tsme_enabled: "Transparent SME (whole-memory encryption) is enabled.",
      ecc_enabled: "ECC memory is enabled — required for SEV-SNP in production.",
      rapl_disabled: "RAPL power reporting is disabled on this platform.",
      ciphertext_hiding_enabled: "Ciphertext hiding is enabled: the host cannot read raw encrypted DRAM contents.",
      alias_check_complete: "The firmware finished checking for memory aliasing before launch, confirming no two addresses map to the same DRAM.",
      tio_enabled: "SEV-TIO (Trusted I/O) is enabled, extending protection to trusted devices.",
    },

    key: {
      "Signing key": "Which key signed the report. VCEK is unique per chip; VLEK is a versioned key loaded by a cloud provider; None means no key.",
      "Author key present": "An author key was used when the guest's ID block was signed (see Author key digest).",
      "Mask chip key": "Chip-unique key usage is masked, hiding the physical chip's identity from the report.",
    },

    tcb: {
      // row labels (left column)
      "FMC": "Firmware Microcontroller component version (present on Turin and newer).",
      "Bootloader": "SVN of the PSP bootloader.",
      "TEE": "SVN of the PSP operating system / trusted execution environment.",
      "SNP": "SVN of the SEV-SNP firmware itself.",
      "Microcode": "CPU microcode patch level.",
      "Build (maj.min.bld)": "SEV-SNP firmware build number, as major.minor.build.",
      // column headers (top row)
      "Current": "The TCB the platform is running right now.",
      "Reported": "The TCB reflected in the derived keys and reported to the guest — may lag Current.",
      "Committed": "The lowest TCB the firmware promises never to roll back below (anti-rollback floor).",
      "Launch": "The TCB that was in effect at the moment this guest was launched.",
    },

    data: {
      "Measurement": "SHA-384 launch measurement — a cryptographic fingerprint of the guest's initial memory, firmware, and VMSA. This is what proves exactly what booted.",
      "Report data": "64 bytes the guest supplied when requesting the report (often a nonce or a hash of a public key). Binds the report to a fresh challenge, preventing replay.",
      "Host data": "32 bytes the host provided at launch. Opaque to firmware; used by the guest owner to carry launch context.",
    },

    ids: {
      "Chip ID": "Unique identifier of the physical CPU that signed the report. (Replaced with placeholders in the sample.)",
      "Report ID": "Unique identifier of this guest instance, assigned by firmware at launch.",
      "Report ID (MA)": "Report ID of this guest's Migration Agent, if one is associated.",
      "Signature": "ECDSA P-384 signature over the first 0x2A0 bytes of the report. Verify it against the AMD-rooted VCEK/VLEK certificate chain.",
    },

    mitigation: {
      "Launch mit. vector": "Mitigations in effect when the guest launched (offset 0x1F8). Can also be mixed into derived keys for MSG_KEY_REQ v2+.",
      "Current mit. vector": "Mitigations in effect when the report was generated (offset 0x200). A bit set here but not in the launch vector means the host applied it via live firmware update while the guest was already running.",
    },
  },
};
