/**
 * WebAuthn im Browser: wandelt die JSON-Optionen des Servers (Base64URL-Text) in die Puffer um, die
 * `navigator.credentials` verlangt, und die Antwort des Geräts zurück in JSON. Kein Geheimnis läuft hier durch:
 * der private Schlüssel bleibt im Gerät.
 */

function b64uToBuf(s: string): ArrayBuffer {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

function bufToB64u(buf: ArrayBuffer | null): string | null {
  if (!buf) return null;
  let s = "";
  for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

interface Desc {
  id: string;
  type: PublicKeyCredentialType;
  transports?: AuthenticatorTransport[];
}

export const webauthnSupported = () => typeof window !== "undefined" && !!window.PublicKeyCredential && !!navigator.credentials;

/** Antwort der Registrierung (Server erwartet `RegisterPublicKeyCredential`). */
export async function createPasskey(options: { publicKey: Record<string, unknown> }): Promise<unknown> {
  const pk = options.publicKey as unknown as { challenge: string; user: { id: string; name: string; displayName: string }; excludeCredentials?: Desc[] };
  const publicKey = {
    ...pk,
    challenge: b64uToBuf(pk.challenge),
    user: { ...pk.user, id: b64uToBuf(pk.user.id) },
    excludeCredentials: (pk.excludeCredentials ?? []).map((c) => ({ ...c, id: b64uToBuf(c.id) })),
  } as unknown as PublicKeyCredentialCreationOptions;
  const cred = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
  if (!cred) throw new Error("Abgebrochen");
  const r = cred.response as AuthenticatorAttestationResponse;
  return {
    id: cred.id,
    rawId: bufToB64u(cred.rawId),
    type: cred.type,
    response: {
      attestationObject: bufToB64u(r.attestationObject),
      clientDataJSON: bufToB64u(r.clientDataJSON),
      transports: typeof r.getTransports === "function" ? r.getTransports() : undefined,
    },
    extensions: cred.getClientExtensionResults(),
  };
}

/** Antwort der Anmeldung (Server erwartet `PublicKeyCredential`). */
export async function getPasskey(options: { publicKey: Record<string, unknown> }): Promise<unknown> {
  const pk = options.publicKey as unknown as { challenge: string; allowCredentials?: Desc[] };
  const publicKey = {
    ...pk,
    challenge: b64uToBuf(pk.challenge),
    allowCredentials: (pk.allowCredentials ?? []).map((c) => ({ ...c, id: b64uToBuf(c.id) })),
  } as unknown as PublicKeyCredentialRequestOptions;
  const cred = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
  if (!cred) throw new Error("Abgebrochen");
  const r = cred.response as AuthenticatorAssertionResponse;
  return {
    id: cred.id,
    rawId: bufToB64u(cred.rawId),
    type: cred.type,
    response: {
      authenticatorData: bufToB64u(r.authenticatorData),
      clientDataJSON: bufToB64u(r.clientDataJSON),
      signature: bufToB64u(r.signature),
      userHandle: bufToB64u(r.userHandle),
    },
    extensions: cred.getClientExtensionResults(),
  };
}

/** Verständliche Meldung zu einem Fehler des Browsers (Abbruch, kein Gerät, …). */
export function passkeyErrorText(e: unknown): string {
  const n = e instanceof DOMException ? e.name : "";
  if (n === "NotAllowedError" || (e instanceof Error && e.message === "Abgebrochen")) return "Abgebrochen oder abgelaufen. Bitte erneut versuchen.";
  if (n === "InvalidStateError") return "Dieses Gerät hat hier schon einen Passkey.";
  if (n === "SecurityError") return "Passkeys brauchen die Adresse aus PATCHWATCH_PUBLIC_URL (HTTPS oder localhost).";
  return "Der Passkey konnte nicht verwendet werden.";
}
