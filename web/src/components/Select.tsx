"use client";

import { Children, isValidElement, useEffect, useId, useLayoutEffect, useRef, useState, type ChangeEvent, type ReactElement, type ReactNode } from "react";
import { NavIcon } from "@/components/Icons";

interface Opt {
  value: string;
  label: string;
  disabled: boolean;
}

function readOptions(children: ReactNode): Opt[] {
  const out: Opt[] = [];
  Children.forEach(children, (c) => {
    if (!isValidElement(c)) return;
    const el = c as ReactElement<{ value?: string | number; disabled?: boolean; children?: ReactNode }>;
    if (el.type !== "option") return;
    const label = Children.toArray(el.props.children).join("");
    out.push({ value: String(el.props.value ?? label), label, disabled: Boolean(el.props.disabled) });
  });
  return out;
}

/**
 * Eigene, zugängliche Auswahl (Listbox-Muster) statt des nativen `<select>`: das native Aufklappmenü schließt sich in modalen
 * Fenstern bei Neuzeichnen oder Fokuswechsel unzuverlässig und lässt sich nicht testen. Gleiche Schnittstelle wie `<select>`
 * (`value`, `onChange(e.target.value)`, `<option>` als Kinder). Maus und Touch wählen per pointerdown, Tastatur: Pfeile, Home/End,
 * Enter/Leertaste, Escape (schließt nur die Auswahl, nicht das Fenster), Tab, Tippen springt zum passenden Eintrag (Typeahead).
 */
export function Select({
  value,
  onChange,
  children,
  disabled,
  className = "",
  "aria-label": ariaLabel,
  id,
}: {
  value: string;
  onChange?: (e: ChangeEvent<HTMLSelectElement>) => void;
  children: ReactNode;
  disabled?: boolean;
  className?: string;
  "aria-label"?: string;
  id?: string;
}) {
  const opts = readOptions(children);
  const uid = useId();
  const listId = `${uid}-list`;
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const [box, setBox] = useState<{ left: number; top: number; width: number; up: boolean } | null>(null);
  const btn = useRef<HTMLButtonElement>(null);
  const list = useRef<HTMLUListElement>(null);
  const typed = useRef<{ s: string; t: number }>({ s: "", t: 0 });
  const current = opts.findIndex((o) => o.value === value);

  function pick(i: number, touch = false) {
    const o = opts[i];
    if (!o || o.disabled) return;
    if (touch) {
      // Auf Touch folgt dem pointerdown noch ein „click“, der nach dem Schließen der Liste das Element darunter träfe (z. B. einen Schalter im Dialog): einmalig verschlucken.
      const swallow = (e: Event) => {
        e.stopPropagation();
        e.preventDefault();
      };
      document.addEventListener("click", swallow, { capture: true, once: true });
      window.setTimeout(() => document.removeEventListener("click", swallow, true), 600);
    }
    setOpen(false);
    btn.current?.focus();
    if (o.value !== value) onChange?.({ target: { value: o.value }, currentTarget: { value: o.value } } as unknown as ChangeEvent<HTMLSelectElement>);
  }

  function show() {
    if (disabled) return;
    const r = btn.current?.getBoundingClientRect();
    if (!r) return;
    const h = Math.min(opts.length * 36 + 8, 280);
    const up = r.bottom + h > window.innerHeight && r.top > h;
    setBox({ left: r.left, top: up ? r.top : r.bottom, width: r.width, up });
    setActive(Math.max(0, current));
    setOpen(true);
  }

  // Schließen bei Klick außerhalb, Scrollen der Seite oder Größenänderung (die Liste ist fest positioniert).
  useEffect(() => {
    if (!open) return;
    const away = (e: PointerEvent) => {
      if (!(e.target instanceof Node)) return;
      if (list.current?.contains(e.target) || btn.current?.contains(e.target)) return;
      setOpen(false);
    };
    const close = (e: Event) => {
      if (e.target instanceof Node && list.current?.contains(e.target)) return;
      setOpen(false);
    };
    document.addEventListener("pointerdown", away, true);
    window.addEventListener("resize", close);
    window.addEventListener("scroll", close, true);
    return () => {
      document.removeEventListener("pointerdown", away, true);
      window.removeEventListener("resize", close);
      window.removeEventListener("scroll", close, true);
    };
  }, [open]);

  useLayoutEffect(() => {
    // Nur die Liste selbst scrollen (scrollIntoView würde auch Seite und Fenster verschieben und die Auswahl über das Scroll-Ereignis schließen).
    const l = list.current;
    const li = open ? l?.querySelector<HTMLElement>(`[data-i="${active}"]`) : null;
    if (l && li) {
      if (li.offsetTop < l.scrollTop) l.scrollTop = li.offsetTop;
      else if (li.offsetTop + li.offsetHeight > l.scrollTop + l.clientHeight) l.scrollTop = li.offsetTop + li.offsetHeight - l.clientHeight;
    }
  }, [open, active]);

  function onKey(e: React.KeyboardEvent) {
    if (disabled) return;
    const last = opts.length - 1;
    const move = (to: number) => {
      let i = Math.max(0, Math.min(last, to));
      const dir = to >= active ? 1 : -1;
      while (opts[i]?.disabled && i + dir >= 0 && i + dir <= last) i += dir;
      setActive(i);
    };
    if (!open) {
      if (["ArrowDown", "ArrowUp", "Enter", " "].includes(e.key)) {
        e.preventDefault();
        show();
      }
      return;
    }
    switch (e.key) {
      case "ArrowDown":
        e.preventDefault();
        move(active + 1);
        break;
      case "ArrowUp":
        e.preventDefault();
        move(active - 1);
        break;
      case "Home":
        e.preventDefault();
        move(0);
        break;
      case "End":
        e.preventDefault();
        move(last);
        break;
      case "Enter":
      case " ":
        e.preventDefault();
        pick(active);
        break;
      case "Escape":
        // Nur die Auswahl schließen, nicht das Fenster dahinter.
        e.preventDefault();
        e.stopPropagation();
        setOpen(false);
        break;
      case "Tab":
        setOpen(false);
        break;
      default:
        if (e.key.length === 1 && !e.ctrlKey && !e.metaKey && !e.altKey) {
          const now = Date.now();
          typed.current = { s: now - typed.current.t > 700 ? e.key.toLowerCase() : typed.current.s + e.key.toLowerCase(), t: now };
          const hit = opts.findIndex((o) => !o.disabled && o.label.toLowerCase().startsWith(typed.current.s));
          if (hit >= 0) setActive(hit);
        }
    }
  }

  return (
    <>
      <button
        ref={btn}
        id={id}
        type="button"
        role="combobox"
        aria-label={ariaLabel}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={open ? listId : undefined}
        aria-activedescendant={open ? `${uid}-o${active}` : undefined}
        disabled={disabled}
        data-select=""
        onClick={() => (open ? setOpen(false) : show())}
        onKeyDown={onKey}
        className={`inline-flex min-h-8 w-full items-center justify-between gap-2 rounded-[3px] border border-control bg-sunk px-2 text-left text-sm font-normal text-fg hover:bg-surface disabled:cursor-not-allowed disabled:opacity-50 max-md:min-h-11 ${className}`}
      >
        <span className="min-w-0 truncate" title={current >= 0 ? opts[current].label : undefined}>
          {current >= 0 ? opts[current].label : ""}
        </span>
        <NavIcon name="chevron" size={14} />
      </button>
      {open && box ? (
        <ul
          ref={list}
          id={listId}
          role="listbox"
          aria-label={ariaLabel}
          style={{ left: box.left, minWidth: box.width, ...(box.up ? { bottom: window.innerHeight - box.top } : { top: box.top }) }}
          className="fixed z-[60] m-0 max-h-70 list-none overflow-auto rounded-[3px] border border-line bg-surface p-1 shadow-lg"
        >
          {opts.map((o, i) => (
            <li
              key={o.value}
              id={`${uid}-o${i}`}
              role="option"
              data-i={i}
              aria-selected={o.value === value}
              aria-disabled={o.disabled || undefined}
              // pointerdown statt click: gilt für Maus und Touch gleich und kommt vor jedem Fokuswechsel.
              onPointerDown={(e) => {
                e.preventDefault();
                pick(i, e.pointerType !== "mouse");
              }}
              onPointerEnter={() => setActive(i)}
              className={`flex min-h-9 cursor-pointer items-center gap-2 rounded-xs px-2 text-sm max-md:min-h-11 ${o.disabled ? "opacity-50" : ""} ${i === active ? "bg-sunk" : ""} ${o.value === value ? "font-semibold" : ""}`}
            >
              <span className="w-4 shrink-0 text-accent">{o.value === value ? "✓" : ""}</span>
              {o.label}
            </li>
          ))}
        </ul>
      ) : null}
    </>
  );
}
