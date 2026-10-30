import { AuthProvider } from "@/components/AuthProvider";
import { Shell } from "@/components/Shell";

export default function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <AuthProvider>
      <Shell>{children}</Shell>
    </AuthProvider>
  );
}
