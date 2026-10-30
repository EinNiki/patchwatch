import type { NextConfig } from "next";

// Die Web-UI hat kein eigenes Backend: Sie spricht ausschließlich mit der Rust-API unter /api/v1.
// In Produktion leitet der Reverse-Proxy /api an den Server (siehe deploy/Caddyfile); nur für die
// lokale Entwicklung (`next dev`) wird /api hier an den Server weitergereicht.
const apiUrl = process.env.PATCHWATCH_API_URL ?? "http://127.0.0.1:8080";

const config: NextConfig = {
  output: "standalone",
  // Nur für `next dev`: erlaubt den Zugriff über 127.0.0.1 (sonst blockiert Next.js die Dev-Ressourcen).
  allowedDevOrigins: ["127.0.0.1"],
  poweredByHeader: false,
  async rewrites() {
    return process.env.NODE_ENV === "development"
      ? [{ source: "/api/:path*", destination: `${apiUrl}/api/:path*` }]
      : [];
  },
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "no-referrer" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
        ],
      },
    ];
  },
};

export default config;
