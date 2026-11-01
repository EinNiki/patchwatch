const FLAVOUR: Record<string, string> = {
  aws: "AWS-Cloud",
  azure: "Azure-Cloud",
  gcp: "Google-Cloud",
  gke: "Google Kubernetes (GKE)",
  gkeop: "GKE On-Prem",
  oracle: "Oracle-Cloud",
  ibm: "IBM-Cloud",
  kvm: "KVM-Gast",
  lowlatency: "Low-Latency",
  raspi: "Raspberry Pi",
  hwe: "Hardware-Enablement (HWE)",
  oem: "OEM-Hardware",
  fips: "FIPS-zertifiziert",
  nvidia: "NVIDIA",
  realtime: "Echtzeit",
  riscv: "RISC-V",
  edge: "Edge",
  bluefield: "NVIDIA BlueField",
  "intel-iotg": "Intel IoT",
  xilinx: "Xilinx",
  snapdragon: "Snapdragon",
  dell300x: "Dell 300x",
  allwinner: "Allwinner",
  aws_fips: "AWS FIPS",
};

/**
 * Lesbare Einordnung eines Kernel-Pakets aus dem Namen, z. B. `linux` → „Standard-Kernel“,
 * `linux-6.12` → „Kernel-Serie 6.12“, `linux-aws-5.4` → „AWS-Cloud, Serie 5.4“.
 * Unbekannte Namen liefern `null`.
 */
export function kernelVariant(pkg: string): string | null {
  if (pkg === "linux") return "Standard-Kernel";
  const m = /^linux-(?:signed-|meta-)?(.+)$/.exec(pkg);
  if (!m) return null;
  const parts = m[1].split("-");
  const series = parts.length > 0 && /^\d+(\.\d+)*$/.test(parts[parts.length - 1]) ? parts.pop() : undefined;
  if (parts.length === 0) return series ? `Kernel-Serie ${series}` : null;
  // Jeder Namensteil einzeln: „azure-edge“ → „Azure-Cloud, Edge“; Unbekanntes bleibt als Rohname stehen.
  const name = parts.map((x) => FLAVOUR[x] ?? x).join(", ");
  return series ? `${name}, Serie ${series}` : name;
}
