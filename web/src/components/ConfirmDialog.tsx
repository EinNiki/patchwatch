"use client";

import { useId, useRef } from "react";
import { useModal } from "@/components/useModal";
import { Button } from "./Controls";
import { NavIcon } from "./Icons";

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
  const titleId = useId();
  useModal(ref, open, onCancel);
  return (
    <dialog ref={ref} aria-labelledby={titleId} aria-modal="true">
      <div className="mb-2 flex items-start justify-between gap-3">
        <h2 id={titleId} className="text-lg font-semibold">
          {title}
        </h2>
        <Button size="icon" aria-label="Schließen" title="Schließen" onClick={onCancel} className="-mr-1 -mt-1">
          <NavIcon name="close" />
        </Button>
      </div>
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
