// Messfunktion für Spaltenabstände (läuft im Browser über page.evaluate(measure, selector)).
/** Läuft im Browser: je sichtbarer Spalte [Kopfzeile, Abstand rechts]; Inhalt = Bounding-Box aller Text-/Kindknoten der Zelle. */
export function measure(sel) {
  const table = document.querySelector(sel);
  const heads = [...table.querySelectorAll("thead th")].filter((th) => th.offsetParent !== null && !th.classList.contains("fill"));
  const rows = [...table.querySelectorAll("tbody tr")].filter((r) => r.offsetParent !== null);
  // Inhalt = Textstrecken (Range je Textknoten) plus schrumpfende Elemente (inline*, Icons). Blockelemente zählen nicht,
  // weil sie immer die ganze Zellbreite einnehmen.
  const extent = (el) => {
    let left = Infinity, right = -Infinity;
    const add = (b) => { if (b.width === 0 || b.height === 0) return; left = Math.min(left, b.left); right = Math.max(right, b.right); };
    const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT);
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      if (!n.textContent.trim()) continue;
      const pe = n.parentElement;
      if (pe && (!pe.offsetParent || getComputedStyle(pe).visibility === "hidden" || pe.closest(".sr-only"))) continue;
      const r = document.createRange();
      r.selectNodeContents(n);
      for (const b of r.getClientRects()) add(b);
    }
    for (const c of el.querySelectorAll("svg, img, *")) {
      if (!c.offsetParent && c.tagName !== "svg") continue;
      if (c.closest(".sr-only")) continue;
      const d = getComputedStyle(c).display;
      if (c.tagName === "svg" || c.tagName === "IMG" || d.startsWith("inline")) add(c.getBoundingClientRect());
    }
    return Number.isFinite(left) ? { left, right } : null;
  };
  const cols = heads.map((th, i) => {
    const label = th.innerText.trim().split("\n")[0].trim() || `Spalte ${i + 1}`;
    const headExt = extent(th.querySelector("button, .th-pad") ?? th);
    const cells = rows.map((r) => [...r.children].filter((c) => c.offsetParent !== null && !c.classList.contains("fill"))[i]).filter(Boolean);
    const ex = cells.map(extent).filter(Boolean);
    const left = Math.min(...ex.map((e) => e.left), headExt?.left ?? Infinity);
    const right = Math.max(...ex.map((e) => e.right), headExt?.right ?? -Infinity);
    return { label, left, right, contentW: Math.round(right - left), cellW: th.getBoundingClientRect().width, headRight: headExt?.right, headLeft: headExt?.left, bodyLeft: ex.length ? Math.min(...ex.map((e) => e.left)) : null, bodyRight: ex.length ? Math.max(...ex.map((e) => e.right)) : null };
  });
  const pairs = [];
  for (let i = 0; i < cols.length - 1; i++) {
    const a = cols[i], b = cols[i + 1];
    // gap: Inhalt (Kopf und Zeilen zusammen) der Spalte a bis Inhalt der Spalte b; headGap: nur Köpfe.
    pairs.push({ pair: `${a.label} → ${b.label}`, gap: Math.round(b.left - a.right), headGap: Math.round(b.headLeft - a.headRight) });
  }
  const sw = document.documentElement.scrollWidth, cw = document.documentElement.clientWidth;
  return { pairs, overflow: sw - cw, cols: cols.map((c) => `${c.label}:${Math.round(c.cellW)}/${c.contentW}`) };
}
