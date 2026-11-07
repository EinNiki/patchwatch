import type { Metadata, Viewport } from "next";
import "@fontsource/atkinson-hyperlegible-next/400.css";
import "@fontsource/atkinson-hyperlegible-next/600.css";
import "@fontsource/ibm-plex-mono/400.css";
import "@fontsource/ibm-plex-mono/500.css";
import "./globals.css";
import { ToastProvider } from "@/components/Toaster";

export const metadata: Metadata = {
  title: { default: "patchwatch", template: "%s · patchwatch" },
  description: "Kernel- und Patch-Stand mit CVE-Abgleich",
  robots: { index: false, follow: false },
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  colorScheme: "light dark",
};

// Setzt Farbschema und eingeklappte Seitenleiste vor dem ersten Rendern (kein Aufblitzen, keine Animation beim Laden).
const THEME_SCRIPT = `try{var t=localStorage.getItem("pw-theme");if(t==="light"||t==="dark")document.documentElement.setAttribute("data-theme",t);if(localStorage.getItem("pw-nav:collapsed")==="1")document.documentElement.setAttribute("data-sb","collapsed")}catch(e){}`;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="de" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }} />
      </head>
      <body>
        <a
          href="#main"
          className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 focus:z-50 focus:border focus:border-control focus:bg-surface focus:px-3 focus:py-2"
        >
          Zum Inhalt springen
        </a>
        <ToastProvider>{children}</ToastProvider>
      </body>
    </html>
  );
}
