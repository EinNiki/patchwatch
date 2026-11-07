/** Versionen, Kernel, Paketnamen und IDs in Monospace. */
export function Mono({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return <span className={`mono break-all ${className}`}>{children}</span>;
}

/** Fügt nach „-“, „.“ und „/“ eine Umbruchmöglichkeit ein: lange Versionen brechen nur dort (nie mitten in einer Zahl). */
export function breakable(text: string): React.ReactNode[] {
  return text.split(/([-./])/).flatMap((part, i) => (/^[-./]$/.test(part) ? [part, <wbr key={i} />] : [part]));
}

/** Version/Kernel/Paket in Monospace, die nur an Bindestrichen, Punkten und Schrägstrichen umbricht (`anywhere` nur als letzter Ausweg). */
export function Ver({ children, className = "" }: { children: string; className?: string }) {
  return <span className={`mono [overflow-wrap:anywhere] ${className}`}>{breakable(children)}</span>;
}
