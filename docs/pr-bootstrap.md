## Was ändert sich?
- Cargo-Workspace, `rust-toolchain.toml` (1.95.0)
- Crate `debversion` (dpkg-Versionsvergleich, wird von Agent und Server genutzt)
- `.github/`: CI, Security, Release, Dependabot, Vorlagen, CODEOWNERS; Actions auf Commit-SHA gepinnt
- `SECURITY.md`, `deny.toml`, README mit Badges, `docs/github-setup.md`

## Geprüft
- cargo fmt, clippy -D warnings, test lokal grün
