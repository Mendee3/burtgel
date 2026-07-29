import { mn } from "../../i18n/mn";
import { useAuth } from "../../lib/auth";

export function TopNav() {
  const { user, logout } = useAuth();

  return (
    <header className="border-b border-border bg-surface px-6 py-3 flex items-center justify-between">
      <span className="text-sm font-semibold text-text">Burtgel</span>
      <div className="flex items-center gap-3 text-sm text-text-secondary">
        <span>{user?.displayName || user?.username}</span>
        <button onClick={() => void logout()} className="text-primary hover:underline">
          {mn.logout}
        </button>
      </div>
    </header>
  );
}
