import type { ButtonHTMLAttributes, InputHTMLAttributes, Ref, SelectHTMLAttributes } from "react";

// Einheitliche Regeln für alle Knöpfe: feste Höhe 32 px (Touch: 44 px), Rahmen immer vorhanden, Zustände nur über Farbe und Symbol,
// nie über die Größe (kein Skalieren beim Drücken). Größen: default (Mindestbreite 7rem), row (feste Breite 7rem für Aktionsreihen),
// wide (feste Breite 10rem, Kopfzeile des Quellenbereichs), icon (quadratisch, nur Symbol). Varianten: default, primary, danger, active
// (eingeschalteter Umschalter, z. B. Stern „Nur Watchlist“; zusätzlich aria-pressed setzen).
const base =
  "inline-flex h-8 items-center justify-center gap-1.5 rounded-[3px] border px-2 text-sm font-semibold whitespace-nowrap transition-[background-color,filter,border-color] duration-(--dur-1) ease-(--ease-out) disabled:cursor-not-allowed disabled:opacity-50 max-md:h-11";
const sizes = {
  default: "min-w-28 px-3",
  row: "w-28",
  wide: "w-40",
  icon: "w-8 px-0 max-md:w-11",
} as const;

export type ButtonSize = keyof typeof sizes;

/** Drehendes Lade-Symbol; bei reduzierter Bewegung steht es still (siehe .run-spin). */
export function Spinner() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" aria-hidden="true" focusable="false" className="run-spin shrink-0">
      <path d="M8 2a6 6 0 1 0 6 6" />
    </svg>
  );
}

export function Button({
  variant = "default",
  size = "default",
  busy = false,
  className = "",
  children,
  disabled,
  ref,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "default" | "primary" | "danger" | "active"; size?: ButtonSize; busy?: boolean; ref?: Ref<HTMLButtonElement> }) {
  const v =
    variant === "primary"
      ? "border-accent bg-accent text-bg hover:brightness-110 active:brightness-90"
      : variant === "active"
        ? "border-accent bg-accent-soft text-accent hover:brightness-95 active:brightness-90"
        : variant === "danger"
        ? "border-crit bg-surface text-crit hover:bg-crit-soft active:bg-crit-soft active:brightness-95"
        : "border-control bg-surface text-fg hover:bg-sunk active:bg-sunk active:brightness-95";
  return (
    // Beschäftigt: Knopf bleibt voll sichtbar (kein „disabled“-Grau) und gleich groß, ist aber nicht bedienbar.
    <button
      type="button"
      ref={ref}
      className={`${base} ${sizes[size]} ${v} ${busy ? "cursor-progress" : ""} ${className}`}
      disabled={disabled}
      aria-busy={busy || undefined}
      {...props}
      onClick={busy ? (e) => e.preventDefault() : props.onClick}
    >
      {busy ? <Spinner /> : null}
      {children}
    </button>
  );
}

export function TextInput({ className = "", ref, ...props }: InputHTMLAttributes<HTMLInputElement> & { ref?: Ref<HTMLInputElement> }) {
  return (
    <input
      ref={ref}
      className={`min-h-8 rounded-[3px] border border-control bg-sunk px-2 py-1 text-sm text-fg placeholder:text-fg3 max-md:min-h-11 ${className}`}
      {...props}
    />
  );
}

export function Select({ className = "", ...props }: SelectHTMLAttributes<HTMLSelectElement>) {
  return <select className={`min-h-8 rounded-[3px] border border-control bg-sunk px-1.5 text-sm text-fg max-md:min-h-11 ${className}`} {...props} />;
}

/** Checkbox mit Beschriftung; die ganze Zeile ist die Trefferfläche (32 px, Touch 44 px). */
export function Checkbox({ label, hint, className = "", ...props }: Omit<InputHTMLAttributes<HTMLInputElement>, "type"> & { label: React.ReactNode; hint?: React.ReactNode }) {
  return (
    <label className={`flex min-h-8 items-start gap-2 py-1 max-md:min-h-11 max-md:items-center ${className}`}>
      <input type="checkbox" className="mt-0.5 size-4 shrink-0 accent-(--accent) max-md:mt-0 max-md:size-5" {...props} />
      <span>
        <span className="font-semibold">{label}</span>
        {hint ? <span className="block text-xs text-fg3">{hint}</span> : null}
      </span>
    </label>
  );
}

export function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="flex flex-col gap-1 text-xs font-semibold text-fg2">
      {label}
      {children}
    </label>
  );
}
