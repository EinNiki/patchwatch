// Lädt .ts/.mts-Dateien in `node --test`, ohne zusätzliches Test-Framework: Typen werden mit dem ohnehin
// installierten TypeScript entfernt (manche Node-Builds haben kein --experimental-strip-types).
import { register } from "node:module";

register("./ts-loader.mjs", import.meta.url);
