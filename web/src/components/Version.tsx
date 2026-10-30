/** Versionen, Kernel, Paketnamen und IDs in Monospace. */
export function Mono({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return <span className={`mono break-all ${className}`}>{children}</span>;
}
