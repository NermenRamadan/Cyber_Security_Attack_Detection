import { createFileRoute, Link, Outlet, useRouterState } from "@tanstack/react-router";
import { LayoutDashboard, Activity, FileText, Bot, LogOut, Shield } from "lucide-react";

const NAV = [
  { to: "/dashboard", label: "Dashboard",   icon: LayoutDashboard },
  { to: "/monitor",   label: "Monitor",     icon: Activity },
  { to: "/logs",      label: "Logs",        icon: FileText },
  { to: "/agent",     label: "AI Agent",    icon: Bot },
] as const;

export const Route = createFileRoute("/_app")({
  component: AppLayout,
});

function AppLayout() {
  const path = useRouterState({ select: (s) => s.location.pathname });

  return (
    <div className="flex min-h-screen flex-col" style={{ background: "var(--background, #0a0f1e)" }}>
      
      {/* ── Top Navbar المدمج والانسيابي (الأفقي البديل للـ Sidebar) ── */}
      <header
        className="fixed top-0 left-0 right-0 z-50 flex h-16 items-center justify-between px-6 transition-all duration-300"
        style={{
          background: "linear-gradient(180deg, rgba(10, 15, 30, 0.7) 0%, rgba(6, 9, 20, 0.6) 100%)",
          borderBottom: "1px solid rgba(255, 255, 255, 0.05)",
          backdropFilter: "blur(20px) saturate(160%)",
          boxShadow: "0 4px 24px rgba(0, 0, 0, 0.3)",
        }}
      >
        {/* Left: Logo & Identity */}
        <div className="flex items-center gap-3">
          <div
            className="grid h-9 w-9 shrink-0 place-items-center rounded-[10px] transition-transform duration-300 hover:scale-105"
            style={{
              background: "linear-gradient(135deg, #00d4ff 0%, #0057ff 100%)",
              boxShadow: "0 0 16px rgba(0, 212, 255, 0.4)",
            }}
          >
            <Shield className="h-5 w-5 text-white" />
          </div>
          <div className="flex flex-col leading-none">
            <span className="text-[14px] font-bold tracking-tight text-white">
              Cyber<span style={{ color: "#00d4ff" }}>Shield</span>
            </span>
            <span className="mt-0.5 text-[9px] uppercase tracking-[0.18em] text-white/40">
              Threat Intelligence
            </span>
          </div>
        </div>

        {/* Center: Horizon Navigation Links */}
        <nav className="flex items-center h-full gap-2">
          {NAV.map(({ to, label, icon: Icon }) => {
            const active = path.startsWith(to);
            return (
              <Link
                key={to}
                to={to}
                className="group flex items-center gap-2 rounded-xl px-4 h-10 text-sm transition-all duration-300 relative overflow-hidden"
                style={{
                  background: active ? "linear-gradient(180deg, rgba(0, 212, 255, 0.12) 0%, rgba(0, 87, 255, 0.02) 100%)" : "transparent",
                  color: active ? "#00d4ff" : "rgba(255, 255, 255, 0.6)",
                  boxShadow: active ? "inset 0 0 12px rgba(0, 212, 255, 0.05)" : "none",
                }}
              >
                {/* تأثير خط التنشيط السفلي المتوهج والناعم */}
                {active && (
                  <span 
                    className="absolute bottom-0 left-2 right-2 h-[2.5px] rounded-t-md animate-pulse"
                    style={{
                      background: "linear-gradient(90deg, #00d4ff 0%, #0057ff 100%)",
                      boxShadow: "0 0 8px #00d4ff",
                    }}
                  />
                )}
                
                {/* تأثير الـ Hover الخلفي الانسيابي */}
                <span className="absolute inset-0 bg-white/[0.02] opacity-0 group-hover:opacity-100 transition-opacity duration-300 pointer-events-none" />

                <Icon className={`h-4 w-4 shrink-0 transition-transform duration-300 group-hover:scale-110 ${active ? "text-[#00d4ff]" : "text-white/60 group-hover:text-white"}`} />
                <span className="transition-colors duration-300 group-hover:text-white font-medium">{label}</span>
              </Link>
            );
          })}
        </nav>

        {/* Right: System Status & Sign Out */}
        <div className="flex items-center gap-4">
          {/* Status badge مدمج بنظام الكبسولة الأفقي */}
          <div 
            className="hidden sm:flex items-center gap-2 rounded-full px-3 py-1.5 transition-all duration-300 border" 
            style={{ 
              background: "rgba(0, 224, 150, 0.04)", 
              borderColor: "rgba(0, 224, 150, 0.1)" 
            }}
          >
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-green-400 opacity-75" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-green-400" />
            </span>
            <span className="text-[11px] font-medium tracking-wide" style={{ color: "#00e096" }}>SYSTEM ACTIVE</span>
          </div>

          {/* الخط الفاصل العمودي الأنيق */}
          <div className="h-5 w-[1px]" style={{ background: "rgba(255, 255, 255, 0.08)" }} />

          {/* Sign out */}
          <Link
            to="/"
            className="group flex items-center gap-2 rounded-xl px-3 py-2 text-sm transition-all duration-300 hover:bg-white/[0.03]"
            style={{ color: "rgba(255, 255, 255, 0.4)" }}
          >
            <LogOut className="h-4 w-4 transition-transform duration-300 group-hover:translate-x-0.5" />
            <span className="hidden md:inline group-hover:text-white/60 transition-colors duration-300">Sign out</span>
          </Link>
        </div>
      </header>

      {/* ── Main content content area ── */}
      {/* الـ pt-16 تضمن عدم تداخل المحتوى مع الـ Navbar العلوي المثبت */}
      <div className="pt-16 flex-1 flex flex-col min-w-0 overflow-x-hidden transition-all duration-300">
        <Outlet />
      </div>
    </div>
  );
}