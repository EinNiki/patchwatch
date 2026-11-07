// In die Zwischenablage kopieren, mit Rückfall für unsichere Kontexte (z. B. http://<IP> im Heimnetz, dort fehlt
// navigator.clipboard). Es wird nichts geloggt und nichts an den Server gesendet.

export interface ClipboardEnv {
  /** `navigator.clipboard.writeText`, falls vorhanden (nur in sicheren Kontexten). */
  writeText?: (text: string) => Promise<void>;
  /** Rückfall: verstecktes Textfeld und `document.execCommand("copy")`; liefert, ob es geklappt hat. */
  legacy?: (text: string) => boolean;
}

export type CopyResult = "clipboard" | "legacy" | "failed";

/** Versucht erst die Clipboard-API, dann den Rückfall. Wirft nie. */
export async function copyText(text: string, env: ClipboardEnv): Promise<CopyResult> {
  if (env.writeText) {
    try {
      await env.writeText(text);
      return "clipboard";
    } catch {
      /* z. B. keine Berechtigung oder Dokument ohne Fokus: Rückfall versuchen */
    }
  }
  try {
    if (env.legacy?.(text)) return "legacy";
  } catch {
    /* Rückfall nicht möglich */
  }
  return "failed";
}

/** Umgebung des Browsers. `host` ist der Container für das versteckte Textfeld: in einem modalen Fenster muss es darin liegen,
 *  sonst ist es inert und lässt sich nicht markieren. */
export function browserEnv(host?: HTMLElement | null): ClipboardEnv {
  const clip = typeof navigator !== "undefined" ? navigator.clipboard : undefined;
  return {
    writeText: clip && typeof clip.writeText === "function" ? (t) => clip.writeText(t) : undefined,
    legacy: (text) => {
      const parent = host ?? document.body;
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.setAttribute("aria-hidden", "true");
      ta.tabIndex = -1;
      // Außerhalb des sichtbaren Bereichs, aber nicht display:none (sonst lässt sich nichts markieren).
      ta.style.cssText = "position:fixed;top:0;left:-9999px;width:1px;height:1px;opacity:0;";
      const before = document.activeElement instanceof HTMLElement ? document.activeElement : null;
      parent.appendChild(ta);
      try {
        ta.focus({ preventScroll: true });
        ta.select();
        ta.setSelectionRange(0, text.length);
        return document.execCommand("copy");
      } finally {
        ta.remove();
        before?.focus({ preventScroll: true });
      }
    },
  };
}
