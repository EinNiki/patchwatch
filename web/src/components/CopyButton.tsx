"use client";

import { useState } from "react";
import { Button } from "./Controls";

export function CopyButton({ text, label = "Kopieren" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <Button
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setDone(true);
          setTimeout(() => setDone(false), 2000);
        } catch {
          /* Zwischenablage nicht verfügbar: Text bleibt markierbar */
        }
      }}
    >
      {done ? "Kopiert" : label}
      <span role="status" className="sr-only">
        {done ? "In die Zwischenablage kopiert" : ""}
      </span>
    </Button>
  );
}
