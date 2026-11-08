import type { ButtonHTMLAttributes, InputHTMLAttributes, Ref, SelectHTMLAttributes } from "react";

// Einheitliche Regeln: 32 px hoch (Touch: 44 px), Mindestbreite 7rem, Zustände hover/active/focus-visible/disabled/busy.
const base =
  "inline-flex min-h-8 min-w-28 items-center justify-center gap-1.5 rounded-[3px] border px-3 py-1 text-sm font-semibold whitespace-nowrap transition-[transform,background-color,filter] duration-(--dur-1) ease-(--ease-out) active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-50 disabled:active:scale-100 max-md:min-h-11";

export function Button({
  variant = "default",
  busy = false,
  className = "",
  children,
  disabled,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "default" | "primary" | "danger"; busy?: boolean }) {
  const v =
    variant === "primary"
      ? "border-accent bg-accent text-bg hover:brightness-110"
      : variant === "danger"
        ? "border-crit bg-surface text-crit hover:bg-crit-soft"
        : "border-control bg-surface text-fg hover:bg-sunk";
  return (
    <button type="button" className={`${base} ${v} ${className}`} disabled={disabled || busy} aria-busy={busy || undefined} {...props}>
      {busy ? <span aria-hidden="true" className="skeleton size-2 rounded-full bg-current" /> : null}
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
