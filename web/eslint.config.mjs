import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

// Rohe <button> sind verboten: Knöpfe kommen aus components/Controls.tsx (Button). Die Dateien unten sind der Bestand, der noch
// eigene Knopf-Bausteine enthält (Tabs, Chips, Zeilenmenüs, Navigation); sie bekommen das einheitliche Verhalten (Übergänge,
// gedrückt, Trefferfläche) über globals.css. Neue Dateien dürfen keine rohen <button> enthalten; die Liste darf nur kleiner werden.
const LEGACY_RAW_BUTTON_FILES = [
  "src/app/(app)/agents/page.tsx",
  "src/app/(app)/cves/page.tsx",
  "src/app/(app)/page.tsx",
  "src/app/(app)/users/page.tsx",
  "src/components/CopyButton.tsx",
  "src/components/FeedSources.tsx",
  "src/components/ForcedPasswordChange.tsx",
  "src/components/HostCves.tsx",
  "src/components/InfoTip.tsx",
  "src/components/RowMenu.tsx",
  "src/components/RunStepper.tsx",
  "src/components/Shell.tsx",
  "src/components/SortHead.tsx",
  "src/components/Toaster.tsx",
];

export default defineConfig([
  ...nextVitals,
  ...nextTs,
  globalIgnores([".next/**", "node_modules/**", "next-env.d.ts"]),
  {
    files: ["src/**/*.tsx"],
    ignores: ["src/components/Controls.tsx", ...LEGACY_RAW_BUTTON_FILES],
    rules: {
      "no-restricted-syntax": ["error", { selector: "JSXOpeningElement[name.name='button']", message: "Rohe <button> sind verboten: Button aus @/components/Controls verwenden." }],
    },
  },
]);
