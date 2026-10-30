## Was ändert sich?
Basis: `chore/bootstrap` (gestapelt, bitte nach dem Bootstrap-PR mergen und Basis auf `main` stellen).

- Crate `patchwatch-agent`: sammelt Hostname, os-release, laufenden Kernel, Kernel-Paket per
  `dpkg -S /boot/vmlinuz-$(uname -r)` (Fallback `linux-image-`), neuesten installierten Kernel
  (gleicher Flavour, Vergleich über `debversion`), reboot-required, offene/Security-Updates,
  Uptime, Proxmox-Erkennung; optional Paketliste
- HTTPS-POST mit Bearer-Token (keine Redirects), Exit-Codes 1–4, Meldungen nach stderr/journald
- `agent/dist`: `.service` (User `patchwatch`, `LoadCredential`), `.timer`, `install.sh` (SHA256-Prüfung)

## Geprüft
- fmt, clippy -D warnings, 24 Tests (Fixtures Ubuntu 22.04/24.04, Debian trixie, Proxmox 9)
- musl-Release 1,9 MB, statisch; Lauf auf echtem Host; Exit 3 bei nicht erreichbarem Server

Closes #<Agent-Issues>
