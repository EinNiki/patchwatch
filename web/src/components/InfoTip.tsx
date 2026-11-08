"use client";

import { useId, useState } from "react";

/**
 * Kleines Info-Symbol mit aufklappbarem Erklärtext: per Maus (Tooltip `title`), Tastatur und Touch bedienbar
 * (ein Tooltip allein wäre auf Touchgeräten nicht erreichbar). Der Text steht nach dem Aufklappen im Fluss, nichts
 * schwebt über anderen Inhalten.
 */
export function InfoTip({ label, text, className = "" }: { label: string; text: string; className?: string }) {
  const [open, setOpen] = useState(false);
  const id = useId();
  return (
    <span className={className}>
      <button
        type="button"
        title={text}
        aria-expanded={open}
        aria-controls={id}
        aria-label={`Erklärung zu „${label}“`}
        onClick={() => setOpen(!open)}
        className="ml-1 inline-flex size-6 items-center justify-center rounded-full align-middle text-fg3 hover:text-fg max-md:size-11"
      >
        <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false">
          <circle cx="8" cy="8" r="6.2" />
          <path d="M8 7.2v4M8 4.8v.1" />
        </svg>
      </button>
      <span id={id} hidden={!open} className="mt-0.5 block text-xs font-normal normal-case text-fg2">
        {text}
      </span>
    </span>
  );
}
