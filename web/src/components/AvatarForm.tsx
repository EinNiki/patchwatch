"use client";

import { useEffect, useId, useRef, useState } from "react";
import { api, ApiError } from "@/lib/api";
import { useAuth } from "@/components/AuthProvider";
import { Avatar } from "@/components/Avatar";
import { Button } from "@/components/Controls";
import { ErrorNote } from "@/components/States";
import { AVATAR_SIZE, MAX_AVATAR_BYTES, cropRect, precheck } from "@/lib/avatar";
import { toast } from "@/lib/toastStore";

/** Kodiert den gewählten Ausschnitt neu: 128×128, WebP (sonst PNG), ohne Metadaten; Qualität sinkt, bis es ≤ 64 KB sind. */
async function encode(canvas: HTMLCanvasElement): Promise<Blob> {
  const blob = (type: string, q?: number) => new Promise<Blob | null>((res) => canvas.toBlob(res, type, q));
  for (const q of [0.9, 0.8, 0.65, 0.5]) {
    const b = await blob("image/webp", q);
    // Manche Browser kennen kein WebP-Kodieren und liefern stattdessen PNG: dann gilt der Typ, den sie wirklich lieferten.
    if (b && (b.type === "image/webp" || b.type === "image/png") && b.size <= MAX_AVATAR_BYTES) return b;
    if (b && b.type === "image/png") break;
  }
  const png = await blob("image/png");
  if (png && png.size <= MAX_AVATAR_BYTES) return png;
  throw new Error("Das Bild ist nach dem Verkleinern noch zu groß. Wähle ein einfacheres Bild.");
}

/** Konto: Profilbild ändern (Zuschneiden im Browser) oder entfernen. */
export function AvatarForm() {
  const { me, setAvatar } = useAuth();
  const input = useRef<HTMLInputElement>(null);
  const canvas = useRef<HTMLCanvasElement>(null);
  const [bmp, setBmp] = useState<ImageBitmap | null>(null);
  const [zoom, setZoom] = useState(1);
  const [px, setPx] = useState(0);
  const [py, setPy] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const id = useId();

  // Vorschau zeichnen: dieselbe Zeichenfläche wird später kodiert.
  useEffect(() => {
    const c = canvas.current;
    if (!c || !bmp) return;
    const ctx = c.getContext("2d");
    if (!ctx) return;
    const { sx, sy, side } = cropRect(bmp.width, bmp.height, zoom, px, py);
    ctx.clearRect(0, 0, AVATAR_SIZE, AVATAR_SIZE);
    ctx.imageSmoothingQuality = "high";
    ctx.drawImage(bmp, sx, sy, side, side, 0, 0, AVATAR_SIZE, AVATAR_SIZE);
  }, [bmp, zoom, px, py]);

  async function choose(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    setError(null);
    // Typ nur an den Bytes prüfen (nicht an Endung oder angegebenem Typ).
    const head = new Uint8Array(await file.slice(0, 16).arrayBuffer());
    const bad = precheck(file.size, head);
    if (bad) return setError(bad);
    try {
      const b = await createImageBitmap(file);
      setZoom(1);
      setPx(0);
      setPy(0);
      setBmp((old) => {
        old?.close();
        return b;
      });
    } catch {
      setError("Die Datei lässt sich nicht als Bild lesen.");
    }
  }

  function cancel() {
    setBmp((old) => {
      old?.close();
      return null;
    });
    setError(null);
  }

  async function save() {
    if (!canvas.current || busy) return;
    setBusy(true);
    setError(null);
    try {
      const blob = await encode(canvas.current);
      await api.put("/auth/avatar", blob, { silent: true });
      const m = await api.get<{ avatar: number | null }>("/auth/me");
      setAvatar(m.avatar ?? null);
      cancel();
      toast.success("Profilbild gespeichert.");
    } catch (e) {
      setError(e instanceof ApiError ? (e.status === 429 ? `Zu viele Versuche. Erneut möglich in ${e.retryAfter ?? 60} Sek.` : e.message) : e instanceof Error ? e.message : "Profilbild konnte nicht gespeichert werden.");
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    setBusy(true);
    try {
      await api.del("/auth/avatar", { what: "Profilbild konnte nicht entfernt werden" });
      setAvatar(null);
      toast.success("Profilbild entfernt.");
    } catch {
      /* Der API-Client hat den Fehler als Toast gemeldet. */
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex max-w-sm flex-col gap-3" role="group" aria-labelledby={`${id}-h`}>
      <h3 id={`${id}-h`} className="font-semibold">
        Profilbild
      </h3>
      <div className="flex items-center gap-3">
        <Avatar name={me.username} version={me.avatar} size={48} />
        <div className="flex flex-wrap gap-2">
          <Button onClick={() => input.current?.click()} disabled={busy}>
            Profilbild ändern
          </Button>
          {me.avatar ? (
            <Button variant="danger" onClick={() => void remove()} disabled={busy}>
              Entfernen
            </Button>
          ) : null}
        </div>
        <input ref={input} type="file" accept="image/png,image/jpeg,image/webp" className="sr-only" tabIndex={-1} aria-label="Bilddatei wählen" onChange={(e) => void choose(e)} />
      </div>
      <p className="text-xs text-fg3">PNG, JPEG oder WebP bis 2 MB. Das Bild wird im Browser auf 128 × 128 Pixel zugeschnitten und ohne Metadaten neu kodiert; es wird nur in dieser Anwendung gespeichert.</p>
      {bmp ? (
        <div className="flex flex-col gap-2 rounded-xs border border-line bg-sunk p-3">
          <canvas ref={canvas} width={AVATAR_SIZE} height={AVATAR_SIZE} className="size-32 self-start rounded-full border border-line" role="img" aria-label="Vorschau des Ausschnitts" />
          <label className="flex items-center gap-2 text-xs font-semibold text-fg2">
            Zoom
            <input type="range" min={1} max={3} step={0.05} value={zoom} onChange={(e) => setZoom(Number(e.target.value))} className="min-w-0 flex-1 accent-(--accent) max-md:min-h-11" />
          </label>
          <label className="flex items-center gap-2 text-xs font-semibold text-fg2">
            Waagerecht
            <input type="range" min={-1} max={1} step={0.05} value={px} onChange={(e) => setPx(Number(e.target.value))} className="min-w-0 flex-1 accent-(--accent) max-md:min-h-11" />
          </label>
          <label className="flex items-center gap-2 text-xs font-semibold text-fg2">
            Senkrecht
            <input type="range" min={-1} max={1} step={0.05} value={py} onChange={(e) => setPy(Number(e.target.value))} className="min-w-0 flex-1 accent-(--accent) max-md:min-h-11" />
          </label>
          <div className="flex gap-2">
            <Button variant="primary" busy={busy} onClick={() => void save()}>
              Speichern
            </Button>
            <Button onClick={cancel} disabled={busy}>
              Abbrechen
            </Button>
          </div>
        </div>
      ) : null}
      {error ? <ErrorNote message={error} /> : null}
    </div>
  );
}
