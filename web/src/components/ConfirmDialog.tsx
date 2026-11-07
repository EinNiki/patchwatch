"use client";

import { useId, useRef } from "react";
import { useModal } from "@/components/useModal";
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
  const titleId = useId();
  useModal(ref, open, onCancel);
  return (
    <dialog ref={ref} aria-labelledby={titleId} aria-modal="true">
      <h2 id={titleId} className="mb-2 text-lg font-semibold">
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
