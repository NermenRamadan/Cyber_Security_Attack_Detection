import { Link, useNavigate, useRouterState } from "@tanstack/react-router";
import { LayoutDashboard, Activity, FileText, Bot, LogOut } from "lucide-react";

const NAV = [
  { to: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { to: "/monitor", label: "Monitor", icon: Activity },
  { to: "/logs", label: "Logs", icon: FileText },
  { to: "/agent", label: "AI Agent", icon: Bot },
] as const;

export function TopNav() {
  const path = useRouterState({ select: (s) => s.location.pathname });
  const navigate = useNavigate();
  const inApp = ["/dashboard", "/monitor", "/logs", "/agent"].some((p) => path.startsWith(p));
  const user = inApp;

  const signOut = async () => {
    navigate({ to: "/" });
  };

  return (
    <header className="sticky top-0 z-30 glass-strong">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-6">
        <Link to="/" className="group flex items-center gap-2.5">
          <div
            className="relative grid h-9 w-9 place-items-center rounded-[10px] ring-1 ring-white/15 transition-transform group-hover:scale-105"
            style={{ background: "var(--gradient-primary)", boxShadow: "var(--shadow-glow)" }}
          >
            <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" style={{ color: "oklch(0.13 0.04 260)" }}>
              <path d="M12 2 L20 5 V12 C20 17 16 21 12 22 C8 21 4 17 4 12 V5 Z" />
              <path d="M9 12 L11 14 L15 10" />
            </svg>
            <span className="pointer-events-none absolute -inset-px rounded-[10px] ring-1 ring-inset ring-white/10" />
          </div>
          <div className="flex flex-col leading-none">
            <span className="text-[15px] font-semibold tracking-tight">
              Cyber<span className="text-gradient">Shield</span>
            </span>
            <span className="mt-0.5 text-[10px] uppercase tracking-[0.18em] text-muted-foreground">Threat Intelligence</span>
          </div>
        </Link>

        {user && (
          <nav className="hidden gap-1 md:flex">
            {NAV.map((n) => {
              const active = path.startsWith(n.to);
              const Icon = n.icon;
              return (
                <Link
                  key={n.to}
                  to={n.to}
                  className={`flex items-center gap-2 rounded-lg px-3 py-2 text-sm transition-all ${
                    active ? "bg-primary/15 text-primary" : "text-muted-foreground hover:bg-white/5 hover:text-foreground"
                  }`}
                >
                  <Icon className="h-4 w-4" />
                  {n.label}
                </Link>
              );
            })}
          </nav>
        )}

        <div className="flex items-center gap-2">
          {user ? (
            <button
              onClick={signOut}
              className="flex items-center gap-2 rounded-lg px-3 py-2 text-sm text-muted-foreground hover:bg-white/5 hover:text-foreground"
            >
              <LogOut className="h-4 w-4" />
              <span className="hidden sm:inline">Sign out</span>
            </button>
          ) : (
            <>
              <Link to="/login" className="rounded-lg px-3 py-2 text-sm text-muted-foreground hover:text-foreground">Sign in</Link>
              <Link
                to="/register"
                className="rounded-lg px-4 py-2 text-sm font-medium text-primary-foreground transition-transform hover:scale-105"
                style={{ background: "var(--gradient-primary)" }}
              >
                Get started
              </Link>
            </>
          )}
        </div>
      </div>
    </header>
  );
}
