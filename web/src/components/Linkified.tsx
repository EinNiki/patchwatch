/** Macht http(s)-URLs in Begründungstexten klickbar (z. B. Proxmox Security Advisories). */
export function Linkified({ text }: { text: string }) {
  const parts = text.split(/(https?:\/\/[^\s]+[^\s.,;:)])/g);
  return (
    <>
      {parts.map((p, i) =>
        /^https?:\/\//.test(p) ? (
          <a key={i} href={p} target="_blank" rel="noopener noreferrer">
            {p}
          </a>
        ) : (
          <span key={i}>{p}</span>
        ),
      )}
    </>
  );
}
