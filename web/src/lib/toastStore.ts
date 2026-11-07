// Toast-Zustand ohne React: aus jeder Stelle aufrufbar (auch aus dem API-Client). Die Anzeige liegt in components/Toaster.tsx.

export type ToastVariant = "success" | "info" | "warning" | "error";

export interface ToastAction {
  label: string;
  onClick: () => void;
}

export interface ToastOptions {
  title?: string;
  action?: ToastAction;
  /** Anzeigedauer in ms; `null` = bleibt bis zum Schließen. Standard je Variante, siehe DURATIONS. */
  duration?: number | null;
}

export interface ToastItem {
  id: number;
  variant: ToastVariant;
  title?: string;
  message: string;
  action?: ToastAction;
  duration: number | null;
  /** Anzahl zusammengefasster gleicher Meldungen ("×3"). */
  count: number;
  /** Zeitpunkt der letzten Meldung; ändert sich beim Zusammenfassen und startet den Ablauf neu. */
  stamp: number;
}

export const DURATIONS: Record<ToastVariant, number | null> = { success: 4000, info: 4000, warning: 8000, error: null };
export const MERGE_WINDOW_MS = 5000;
export const MAX_VISIBLE = 4;

export interface ToastState {
  /** Alle offenen Meldungen in Eingangsreihenfolge; angezeigt werden die ersten MAX_VISIBLE, der Rest wartet. */
  items: readonly ToastItem[];
}

export function createToastStore(now: () => number = Date.now) {
  let state: ToastState = { items: [] };
  let nextId = 1;
  const listeners = new Set<() => void>();
  const set = (items: readonly ToastItem[]) => {
    state = { items };
    listeners.forEach((l) => l());
  };

  function push(variant: ToastVariant, message: string, opts: ToastOptions = {}): number {
    const t = now();
    // Gleiche Meldung (Variante, Titel, Text) innerhalb von 5 s: zählen statt stapeln.
    const same = [...state.items].reverse().find((x) => x.variant === variant && x.message === message && x.title === opts.title && t - x.stamp <= MERGE_WINDOW_MS);
    if (same) {
      set(state.items.map((x) => (x === same ? { ...x, count: x.count + 1, stamp: t } : x)));
      return same.id;
    }
    const id = nextId++;
    const duration = opts.duration === undefined ? DURATIONS[variant] : opts.duration;
    set([...state.items, { id, variant, title: opts.title, message, action: opts.action, duration, count: 1, stamp: t }]);
    return id;
  }

  return {
    getState: () => state,
    subscribe(fn: () => void) {
      listeners.add(fn);
      return () => void listeners.delete(fn);
    },
    push,
    dismiss(id: number) {
      if (state.items.some((x) => x.id === id)) set(state.items.filter((x) => x.id !== id));
    },
    clear() {
      if (state.items.length) set([]);
    },
  };
}

export type ToastStore = ReturnType<typeof createToastStore>;

/** Sichtbar sind die ersten MAX_VISIBLE; weitere rücken nach, sobald Platz frei wird. */
export function visible(items: readonly ToastItem[]): readonly ToastItem[] {
  return items.slice(0, MAX_VISIBLE);
}

export const store = createToastStore();

/** Ohne React aufrufbar: `import { toast } from "@/lib/toastStore"`. */
export const toast = {
  success: (message: string, opts?: ToastOptions) => store.push("success", message, opts),
  info: (message: string, opts?: ToastOptions) => store.push("info", message, opts),
  warning: (message: string, opts?: ToastOptions) => store.push("warning", message, opts),
  error: (message: string, opts?: ToastOptions) => store.push("error", message, opts),
  dismiss: (id: number) => store.dismiss(id),
  clear: () => store.clear(),
};
