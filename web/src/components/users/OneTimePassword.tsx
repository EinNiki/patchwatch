import { Button } from "@/components/Controls";
import { CodeField } from "@/components/CopyButton";
import { Dialog } from "@/components/Dialog";

/** Einmalpasswort: nur jetzt sichtbar (der Server speichert nur den Hash), muss beim ersten Anmelden geändert werden. */
export function OneTimePassword({ name, password, onDone }: { name: string; password: string | null; onDone: () => void }) {
  return (
    <Dialog open={password !== null} title={`Einmalpasswort für ${name}`} onClose={onDone} dismissible={false}>
      <p className="mb-3 border-l-4 border-warn bg-warn-soft px-3 py-2 text-warn">
        Dieses Passwort wird <strong>nur jetzt</strong> angezeigt und lässt sich nicht erneut abrufen. Gib es sicher weiter; {name} muss es bei der ersten Anmeldung ändern.
      </p>
      <p className="mb-1 text-xs font-semibold text-fg2">Einmalpasswort kopieren</p>
      <CodeField className="mb-4" text={password ?? ""} label="Einmalpasswort kopieren" />
      <div className="flex justify-end">
        <Button variant="primary" onClick={onDone}>
          Fertig, Passwort weitergegeben
        </Button>
      </div>
    </Dialog>
  );
}
