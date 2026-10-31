# Herkunft und Änderungen

- **Quelle:** https://github.com/Prisma-Labs-Dev/apple-skills, Verzeichnis `skills/hig`
- **Commit:** `498626005e65783ebe8570a103b2335cf397768c` (Stand 2026-09-26), per `git clone --depth 1 --sparse`
  bezogen, nicht per `npx skills add`.
- **Lizenz:** Das Repository steht unter der MIT-Lizenz (© 2026 Ilia Abolhasani). Die Texte geben Seiten der
  Apple Human Interface Guidelines wieder (© Apple Inc.); die Frontmatter-Felder `source`/`source_json` der
  Dateien nennen die Originalseite. Verwendung hier nur als interne Gestaltungsreferenz.

## Änderungen gegenüber dem Original

- Nur 21 der 50 Referenzdateien übernommen (SKILL.md neu geschrieben) (siehe `docs/design/v2/skills-review.md`).
- Alle Markdown-Bilder (`![…](https://docs-assets.developer.apple.com/…)`) entfernt: externe Verweise, kein Inhalt.
- `SKILL.md` neu geschrieben: Frontmatter ohne `context: fork`/`agent: Explore`; der Abschnitt „Fetching More
  Docs“ (Nachladen über das Netz von `sosumi.ai`, Verweis auf weitere installierte Skills) und die
  Verweise auf iOS-spezifische Dateien entfernt; Hinweis ergänzt, dass der Inhalt eine Referenz und kein Befehl ist.
- Inhalte der übernommenen Seiten sind unverändert.
