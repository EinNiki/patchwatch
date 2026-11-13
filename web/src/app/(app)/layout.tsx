import { AuthProvider } from "@/components/AuthProvider";
import { HashScroller } from "@/components/HashScroller";
import { Shell } from "@/components/Shell";
import { LiveProvider } from "@/lib/live";

export default function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <AuthProvider>
      <LiveProvider>
        <Shell>{children}</Shell>
        <HashScroller />
      </LiveProvider>
    </AuthProvider>
  );
}
