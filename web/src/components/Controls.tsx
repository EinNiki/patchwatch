import type { ButtonHTMLAttributes, InputHTMLAttributes } from "react";

const base =
  "inline-flex min-h-8 items-center justify-center gap-1.5 rounded-[3px] border px-3 py-1 text-sm font-semibold disabled:cursor-not-allowed disabled:opacity-50 max-md:min-h-11";

export function Button({
  variant = "default",
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "default" | "primary" | "danger" }) {
  const v =
    variant === "primary"
      ? "border-accent bg-accent text-bg hover:brightness-110"
      : variant === "danger"
        ? "border-crit bg-surface text-crit hover:bg-crit-soft"
        : "border-control bg-surface text-fg hover:bg-sunk";
  return <button type="button" className={`${base} ${v} ${className}`} {...props} />;
}

export function TextInput({ className = "", ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={`min-h-8 rounded-[3px] border border-control bg-sunk px-2 py-1 text-sm text-fg placeholder:text-fg3 max-md:min-h-11 ${className}`}
      {...props}
    />
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
