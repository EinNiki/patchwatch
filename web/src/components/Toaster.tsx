"use client";

import { createContext, useCallback, useContext, useEffect, useRef, useState, useSyncExternalStore } from "react";
import { Icon } from "@/components/Icons";
import { store, toast, visible, type ToastItem, type ToastVariant } from "@/lib/toastStore";

type ToastApi = typeof toast;
const Ctx = createContext<ToastApi>(toast);

/** Im Wurzel-Layout einmal einbinden: rendert den Bereich oben rechts. Die Meldungen selbst kommen aus `toast` / `useToast()`. */
export function ToastProvider({ children }: { children: React.ReactNode }) {
  return (
    <Ctx.Provider value={toast}>
      {children}
      <ToastRegion />
    </Ctx.Provider>
  );
}

export function useToast(): ToastApi {
  return useContext(Ctx);
}

const LEAVE_MS = 160;
const reducedMotion = () => typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

const TONE: Record<ToastVariant, string> = {
  success: "border-ok text-ok",
  info: "border-accent text-accent",
  warning: "border-warn text-warn",
  error: "border-crit text-crit",
};

function VariantIcon({ variant }: { variant: ToastVariant }) {
  if (variant === "success") return <Icon name="ok" />;
  if (variant === "warning") return <Icon name="warn" />;
  if (variant === "error") return <Icon name="crit" />;
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" aria-hidden="true" focusable="false" className="shrink-0">
      <circle cx="8" cy="8" r="6.25" />
      <path d="M8 7.25v3.5M8 5v.01" />
    </svg>
  );
}

function ToastView({ item }: { item: ToastItem }) {
  const [paused, setPaused] = useState(false);
  const [leaving, setLeaving] = useState(false);
  const remaining = useRef(item.duration ?? 0);

  const close = useCallback(() => {
    setLeaving(true);
    window.setTimeout(() => store.dismiss(item.id), reducedMotion() ? 0 : LEAVE_MS);
  }, [item.id]);

  // Eine zusammengefasste Wiederholung startet die Anzeigedauer neu.
  useEffect(() => {
    remaining.current = item.duration ?? 0;
  }, [item.stamp, item.duration]);

  // Ablauf: bei Hover/Fokus angehalten, danach mit der Restzeit fortgesetzt.
  useEffect(() => {
    if (item.duration === null || paused || leaving) return;
    const started = Date.now();
    const timer = window.setTimeout(close, remaining.current);
    return () => {
      window.clearTimeout(timer);
      remaining.current -= Date.now() - started;
    };
  }, [item.stamp, item.duration, paused, leaving, close]);

  return (
    <li
      data-toast={item.variant}
      data-leaving={leaving || undefined}
      onPointerEnter={() => setPaused(true)}
      onPointerLeave={() => setPaused(false)}
      onFocus={() => setPaused(true)}
      onBlur={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget as Node | null)) setPaused(false);
      }}
      className={`toast pointer-events-auto flex items-start gap-2 border-l-4 border-y border-r bg-surface px-3 py-2 shadow-lg ${TONE[item.variant].split(" ")[0]}`}
    >
      <span className={`mt-0.5 ${TONE[item.variant].split(" ")[1]}`}>
        <VariantIcon variant={item.variant} />
      </span>
      {/* Die Rolle sitzt innen: ein <li> mit eigener Rolle wäre kein Listeneintrag mehr (axe: list, aria-allowed-role). */}
      <div role={item.variant === "error" ? "alert" : "status"} className="min-w-0 flex-1 text-fg">
        {item.title ? <p className="font-semibold">{item.title}</p> : null}
        <p className={`${item.title ? "text-sm text-fg2" : ""} break-words`}>
          {item.message}
          {item.count > 1 ? (
            <span className="ml-2 inline-block rounded-[3px] bg-sunk px-1.5 text-xs font-semibold text-fg2" aria-label={`${item.count} Mal`}>
              ×{item.count}
            </span>
          ) : null}
        </p>
        {item.action ? (
          <button
            type="button"
            onClick={() => {
              item.action?.onClick();
              close();
            }}
            className="mt-1 min-h-8 font-semibold text-accent underline underline-offset-2 hover:no-underline max-md:min-h-11"
          >
            {item.action.label}
          </button>
        ) : null}
      </div>
      <button
        type="button"
        onClick={close}
        className="-my-1 -mr-1 inline-flex min-h-8 min-w-8 items-center justify-center rounded-[3px] text-fg2 hover:bg-sunk hover:text-fg max-md:min-h-11 max-md:min-w-11"
      >
        <span aria-hidden="true">×</span>
        <span className="sr-only">Meldung schließen</span>
      </button>
    </li>
  );
}

function ToastRegion() {
  const items = useSyncExternalStore(store.subscribe, () => store.getState().items, () => store.getState().items);
  const shown = visible(items);
  const waiting = items.length - shown.length;
  return (
    <div
      role="region"
      aria-label="Benachrichtigungen"
      // top-16: unterhalb der Kopfzeile, damit eine stehende Fehlermeldung die Aktionsschaltflächen der Seite nicht verdeckt.
      // Escape schließt die Meldung, in der der Fokus steht (sonst die älteste sichtbare), ohne Dialoge darunter zu berühren.
      onKeyDown={(e) => {
        if (e.key !== "Escape") return;
        const li = (e.target as HTMLElement).closest("li[data-toast]");
        const idx = li ? [...e.currentTarget.querySelectorAll("li[data-toast]")].indexOf(li) : 0;
        const target = shown[Math.max(0, idx)];
        if (target) {
          e.stopPropagation();
          store.dismiss(target.id);
        }
      }}
      className="pointer-events-none fixed right-4 top-16 z-50 flex w-[min(24rem,calc(100vw-2rem))] flex-col gap-2"
    >
      <ul className="m-0 flex list-none flex-col gap-2 p-0">
        {shown.map((t) => (
          <ToastView key={t.id} item={t} />
        ))}
      </ul>
      {waiting > 0 ? (
        <p className="pointer-events-auto self-end rounded-[3px] bg-sunk px-2 py-0.5 text-xs text-fg2">+{waiting} weitere</p>
      ) : null}
    </div>
  );
}
