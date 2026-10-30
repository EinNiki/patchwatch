"use client";

import { useEffect, useRef } from "react";
import { Button } from "./Controls";

/** Bestätigung per natives <dialog> (Fokusfalle, Escape, Backdrop inklusive). */
export function ConfirmDialog({
  open,
  title,
  children,
  confirmLabel,
  danger,
  onConfirm,
  onCancel,
}: {
  open: boolean;
  title: string;
  children: React.ReactNode;
  confirmLabel: string;
  danger?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);
  return (
    <dialog ref={ref} onCancel={onCancel} aria-labelledby="dlg-title">
      <h2 id="dlg-title" className="mb-2 text-base font-semibold">
        {title}
      </h2>
      <div className="mb-4 text-fg2">{children}</div>
      <div className="flex justify-end gap-2">
        <Button onClick={onCancel}>Abbrechen</Button>
        <Button variant={danger ? "danger" : "primary"} onClick={onConfirm}>
          {confirmLabel}
        </Button>
      </div>
    </dialog>
  );
}
