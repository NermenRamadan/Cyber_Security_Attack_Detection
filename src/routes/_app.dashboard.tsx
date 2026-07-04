import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { Shield, Target, TrendingUp, AlertTriangle, Globe } from "lucide-react";
import {
  AreaChart, Area, ResponsiveContainer, XAxis, YAxis, Tooltip,
  CartesianGrid, PieChart, Pie, Cell
} from "recharts";
import { severityPillClass } from "../lib/mockAttacks";

export const Route = createFileRoute("/_app/dashboard")({
  component: Dashboard,
  head: () => ({ meta: [{ title: "Dashboard – CyberShield" }] }),
});

const CHART_COLORS = ["#ef4444", "#00f0ff", "#f59e0b", "#a78bfa", "#38bdf8", "#5dd8b8"];

const CARD_STYLE = {
  background: "rgba(13, 22, 50, 0.4)",
  border: "1px solid rgba(255, 255, 255, 0.05)",
  borderRadius: 16,
  backdropFilter: "blur(20px)",
};

interface StatCardProps {
  icon: any;
  label: string;
  value: string | number;
  sub?: string;
  color?: string;
  alert?: boolean;
  trend?: string;
}

function StatCard({ icon: Icon, label, value, sub, color = "#00f0ff", alert = false, trend }: StatCardProps) {
  return (
    <div 
      style={{ ...CARD_STYLE, borderColor: alert ? "rgba(239,68,68,0.25)" : "rgba(255,255,255,0.05)" }}
      className="relative overflow-hidden p-5 transition-all duration-300 hover:border-white/10"
    >
      {alert && <div className="absolute inset-0 animate-pulse" style={{ background: "rgba(239,68,68,0.02)" }} />}
      <div className="relative flex items-start justify-between">
        <div className="flex-1">
          <p className="text-[10px] uppercase tracking-[0.15em] mb-1.5 text-white/40">{label}</p>
          <p className="text-3xl font-bold tracking-tight mb-1 font-mono" style={{ color }}>{value}</p>
          {sub && <p className="text-xs text-white/35 font-medium">{sub}</p>}
          {trend && <p className="text-[11px] mt-1.5 text-emerald-400 font-medium">{trend}</p>}
        </div>
        <div className="grid h-10 w-10 place-items-center rounded-xl" style={{ background: `${color}12` }}>
          <Icon className="h-5 w-5" style={{ color }} />
        </div>
      </div>
    </div>
  );
}

function Dashboard() {
  const [dbAttacks, setDbAttacks] = useState<any[]>([]);
  const [currentTime, setCurrentTime] = useState<Date>(new Date());

  const startTime = useMemo(() => {
    const saved = localStorage.getItem("monitoring_start_time");
    if (saved) return new Date(saved);
    const now = new Date();
    localStorage.setItem("monitoring_start_time", now.toISOString());
    return now;
  }, []);

  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    const load = async () => {
      try {
        const r = await fetch("http://127.0.0.1:8000/api/logs?limit=500");
        if (r.ok) setDbAttacks((await r.json()) ?? []);
      } catch (err) {
        console.error("Dashboard pool error:", err);
      }
    };
    load();
    const interval = setInterval(load, 3000);
    return () => { clearInterval(timer); clearInterval(interval); };
  }, []);

  const all = useMemo(() => dbAttacks.slice(0, 500), [dbAttacks]);
  const attacksOnly = useMemo(() => all.filter(r => r.status !== "normal"), [all]);
  const normalOnly = useMemo(() => all.filter(r => r.status === "normal"), [all]);
  
  const attackCount = attacksOnly.length;
  const totalLogs = all.length;

  const safetyScore = useMemo(() => {
    if (!totalLogs) return 100;
    return Math.max(0, Math.round(((totalLogs - attackCount) / totalLogs) * 100));
  }, [totalLogs, attackCount]);

  const durationText = useMemo(() => {
    const diff = Math.floor((currentTime.getTime() - startTime.getTime()) / 60000);
    if (diff < 1) return "Just initialized";
    if (diff < 60) return `Active for ${diff}m`;
    return `Active for ${Math.floor(diff / 60)}h`;
  }, [startTime, currentTime]);

  const overTime = useMemo(() => {
    const buckets: Record<string, number> = {};
    for (let i = 11; i >= 0; i--) {
      const d = new Date(Date.now() - i * 30 * 60 * 1000);
      buckets[d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false })] = 0;
    }
    attacksOnly.forEach(a => {
      const k = new Date(a.detected_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false });
      if (k in buckets) buckets[k]++;
    });
    return Object.entries(buckets).map(([time, count]) => ({ time, count }));
  }, [attacksOnly]);

  const distribution = useMemo(() => {
    const m: Record<string, number> = {};
    attacksOnly.forEach(a => { if(a.attack_type) m[a.attack_type] = (m[a.attack_type] || 0) + 1; });
    return Object.entries(m).filter(([, v]) => v > 0).map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value).slice(0, 5);
  }, [attacksOnly]);

  const sources = useMemo(() => {
    const m: Record<string, number> = {};
    attacksOnly.forEach(a => { const c = a.source_ip || "Unknown IP"; m[c] = (m[c] || 0) + 1; });
    return Object.entries(m).map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value).slice(0, 4);
  }, [attacksOnly]);

  const recentAlerts = useMemo(() => attacksOnly.slice(0, 4), [attacksOnly]);
  const last = attacksOnly[0];

  const tooltipStyle = {
    background: "rgba(10,15,30,0.95)",
    border: "1px solid rgba(0,240,255,0.15)",
    borderRadius: 8,
    fontSize: 12,
    color: "#fff"
  };

  return (
    <main className="px-6 py-6 text-white min-h-screen">
      
      {/* Top Heading Group */}
      <div className="mb-6 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold uppercase tracking-[0.15em] text-white">
            Security Operations Center
          </h1>
          <p className="text-xs mt-1 text-white/40">
            Live Stream — {currentTime.toLocaleTimeString()} &nbsp;·&nbsp; {new Date().toLocaleDateString()}
          </p>
        </div>
        <div className="flex items-center gap-2 self-start sm:self-center bg-emerald-500/5 border border-emerald-500/10 rounded-full px-3 py-1 text-xs text-emerald-400">
          <span className="relative flex h-2 w-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-400" />
          </span>
          Telemetry Online
        </div>
      </div>

      {/* Grid: 4 Metric Cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4 mb-5">
        <StatCard icon={Shield} label="Total Events" value={totalLogs} sub="Total captured packets" color="#00f0ff" trend={totalLogs > 0 ? `+${totalLogs} logs` : undefined} />
        <StatCard icon={Target} label="Active Threats" value={attackCount} sub={durationText} color="#ef4444" alert={attackCount > 0} trend={attackCount > 0 ? `${attackCount} spikes` : undefined} />
        <StatCard icon={Shield} label="Safe Packets" value={normalOnly.length} sub="Verified normal traffic" color="#00e096" />
        <StatCard icon={TrendingUp} label="Security Index" value={`${safetyScore}%`} sub={safetyScore > 80 ? "Optimal Status" : safetyScore > 60 ? "Warning Alert" : "Critical Risk"} color={safetyScore > 80 ? "#00e096" : "#f59e0b"} />
      </div>

      {/* Map & Critical Intel Row */}
      <div className="grid gap-4 lg:grid-cols-3 mb-5">
        
        {/* Cinematic Reconstructed Threat Map Container */}
        <div className="lg:col-span-2 flex flex-col p-5" style={CARD_STYLE}>
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-semibold tracking-wide text-white/80">Threat Intersection Map</h3>
              <p className="text-[11px] text-white/30">Geographical routing of ingress threat intelligence</p>
            </div>
            <Globe className="h-4 w-4 text-cyan-400/60 animate-spin" style={{ animationDuration: '15s' }} />
          </div>
          
          {/* Reconstructed visual Map grid replacement */}
          <div className="flex-1 min-h-[260px] bg-white/[0.01] rounded-xl border border-white/5 relative overflow-hidden flex flex-col justify-between p-4">
            <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-cyan-500/5 via-transparent to-transparent pointer-events-none" />
            
            {/* Live stream overlay badges */}
            <div className="flex flex-wrap gap-2 z-10">
              {attacksOnly.slice(0, 3).map((atk, index) => (
                <div key={index} className="flex items-center gap-2 bg-slate-900/80 border border-white/5 rounded-lg px-2.5 py-1.5 text-[11px]">
                  <span className="h-1.5 w-1.5 rounded-full animate-ping" style={{ background: atk.severity === "Critical" ? "#ef4444" : "#f59e0b" }} />
                  <span className="font-mono text-cyan-400 text-xs">{atk.source_ip || "0.0.0.0"}</span>
                  <span className="text-white/40">→</span>
                  <span className="text-white/70 font-medium">{atk.attack_type}</span>
                </div>
              ))}
              {attacksOnly.length === 0 && (
                <p className="text-xs text-white/30 italic p-2">Awaiting spatial intercept vectors...</p>
              )}
            </div>

            {/* Simulated target nodes structure */}
            <div className="flex justify-around items-center w-full py-6">
              <div className="text-center relative">
                <div className="h-12 w-12 rounded-full border border-dashed border-cyan-500/30 flex items-center justify-center bg-cyan-950/20">
                  <span className="h-2 w-2 rounded-full bg-cyan-400 shadow-[0_0_8px_#00f0ff]" />
                </div>
                <p className="text-[10px] text-white/40 mt-1 font-mono">NODE_EDGE_01</p>
              </div>
              <div className="h-[1px] flex-1 bg-gradient-to-r from-transparent via-red-500/30 to-transparent relative mx-2">
                {attackCount > 0 && <span className="absolute w-1.5 h-1.5 bg-red-400 rounded-full top-1/2 -translate-y-1/2 left-0 animate-[ping_2s_infinite]" style={{ animationDelay: '0.5s' }} />}
              </div>
              <div className="text-center">
                <div className="h-16 w-16 rounded-full border border-double border-red-500/20 flex items-center justify-center bg-red-950/10 relative">
                  <span className="absolute inset-0 rounded-full animate-ping bg-red-500/5 duration-1000" />
                  <Target className="h-5 w-5 text-red-400" />
                </div>
                <p className="text-[10px] text-red-400/80 mt-1 font-mono font-semibold">CORE_SRV_INSPECT</p>
              </div>
            </div>

            <div className="flex justify-between items-center text-[10px] text-white/30 border-t border-white/5 pt-2 font-mono">
              <span>BOUND_PORT: 8000 (FASTAPI)</span>
              <span>ENGINE: XGBOOST_MODEL</span>
            </div>
          </div>
        </div>

        {/* Dynamic Critical Threat Card */}
        <div style={{ ...CARD_STYLE, borderColor: last ? "rgba(239,68,68,0.2)" : "rgba(255,255,255,0.05)" }}
          className="relative overflow-hidden p-5 flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-white/70">
              Critical Payload Target
            </h3>
            {last && (
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${severityPillClass(last.severity)}`}>
                {last.severity}
              </span>
            )}
          </div>
          
          {last ? (
            <>
              <div className="flex justify-center mb-4">
                <div className="h-14 w-14 rounded-full grid place-items-center"
                  style={{ background: "rgba(239,68,68,0.08)", border: "1px solid rgba(239,68,68,0.25)" }}>
                  <AlertTriangle className="h-6 w-6 text-red-500" />
                </div>
              </div>
              <div className="space-y-2 flex-1">
                {[
                  { k: "Threat Variant", v: last.attack_type },
                  { k: "Source Vector", v: last.source_ip },
                  { k: "Protocol Layer", v: last.protocol },
                  { k: "Time Absolute", v: new Date(last.detected_at).toLocaleTimeString() },
                ].map(({ k, v }) => (
                  <div key={k} className="flex justify-between text-xs border-b pb-1.5 border-white/5">
                    <span className="text-white/40">{k}</span>
                    <span className="font-mono text-white/90 truncate max-w-[150px]">{v || "—"}</span>
                  </div>
                ))}
              </div>
              {last.solution && (
                <div className="mt-3 rounded-xl p-3 text-[11px] bg-red-500/5 border border-red-500/10 text-white/60">
                  ⚡ {last.solution}
                </div>
              )}
            </>
          ) : (
            <div className="flex flex-1 flex-col items-center justify-center gap-2">
              <Shield className="h-10 w-10 text-emerald-400" />
              <p className="text-sm text-emerald-400">Zero Flags Raised</p>
              <p className="text-xs text-white/30 text-center">No structural discrepancies found</p>
            </div>
          )}
        </div>
      </div>

      {/* Grid: Charts & Feeds */}
      <div className="grid gap-4 lg:grid-cols-3">

        {/* Pie Breakdown */}
        <div style={CARD_STYLE} className="p-5">
          <h3 className="text-sm font-semibold text-white/80">Threat Classification</h3>
          <p className="text-[11px] text-white/30 mb-3">Distribution arrays of detected anomalies</p>
          {distribution.length > 0 ? (
            <>
              <div className="h-44">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={distribution} dataKey="value" nameKey="name" innerRadius={45} outerRadius={65} paddingAngle={4}>
                      {distribution.map((_, i) => (
                        <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} stroke="#0c122b" strokeWidth={2} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={tooltipStyle} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div className="mt-2 space-y-1.5">
                {distribution.map((d, i) => (
                  <div key={d.name} className="flex items-center justify-between text-xs">
                    <span className="flex items-center gap-2 text-white/70">
                      <span className="h-2 w-2 rounded-full" style={{ background: CHART_COLORS[i % CHART_COLORS.length] }} />
                      {d.name}
                    </span>
                    <span className="font-mono font-bold" style={{ color: CHART_COLORS[i % CHART_COLORS.length] }}>{d.value}</span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="flex h-44 items-center justify-center text-xs text-white/30">No categorical signatures parsed</div>
          )}
        </div>

        {/* Timeline Area Chart */}
        <div style={CARD_STYLE} className="p-5">
          <h3 className="text-sm font-semibold text-white/80">Temporal Attack Vectors</h3>
          <p className="text-[11px] text-white/30 mb-3">Frequency distribution parsed dynamically</p>
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={overTime}>
                <defs>
                  <linearGradient id="redGlow" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#ef4444" stopOpacity={0.4} />
                    <stop offset="100%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.02)" />
                <XAxis dataKey="time" stroke="rgba(255,255,255,0.2)" fontSize={9} interval={2} tickLine={false} />
                <YAxis stroke="rgba(255,255,255,0.2)" fontSize={10} tickLine={false} />
                <Tooltip contentStyle={tooltipStyle} />
                <Area type="monotone" dataKey="count" stroke="#ef4444" fill="url(#redGlow)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Ingress Logs & Origin Vectors */}
        <div style={CARD_STYLE} className="p-5 flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-semibold text-white/80">Real-time Threat Ingress</h3>
            <p className="text-[11px] text-white/30 mb-3">Sequential pipeline sequence logs</p>
            {recentAlerts.length > 0 ? (
              <div className="space-y-2">
                {recentAlerts.map((a, i) => {
                  const sev = a.severity;
                  const col = sev === "Critical" ? "#ef4444" : sev === "High" ? "#f59e0b" : sev === "Medium" ? "#00f0ff" : "#6b7280";
                  return (
                    <div key={i} className="flex items-start gap-3 rounded-xl p-2.5 bg-white/[0.01] border border-white/5">
                      <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full" style={{ background: col, boxShadow: `0 0 6px ${col}` }} />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-xs font-semibold truncate text-white/90">{a.attack_type}</span>
                          <span className="text-[9px] text-white/30 font-mono">
                            {new Date(a.detected_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false })}
                          </span>
                        </div>
                        <p className="text-[10px] mt-0.5 truncate font-mono text-white/40">{a.source_ip}</p>
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="flex h-32 flex-col items-center justify-center text-xs text-white/30">No telemetry frames logged</div>
            )}
          </div>

          {/* Sources Progress Bars */}
          {sources.length > 0 && (
            <div className="mt-4 pt-3 border-t border-white/5">
              <p className="text-[10px] uppercase tracking-wider text-white/40 mb-2">Primary Host Vectors</p>
              <div className="space-y-2">
                {sources.map(s => {
                  const max = sources[0]?.value || 1;
                  return (
                    <div key={s.name}>
                      <div className="flex justify-between text-[10px] mb-0.5 font-mono">
                        <span className="text-cyan-400">{s.name}</span>
                        <span className="text-white/40">{s.value} hits</span>
                      </div>
                      <div className="h-1 rounded-full bg-white/5 overflow-hidden">
                        <div className="h-full rounded-full transition-all duration-500" style={{ width: `${(s.value / max) * 100}%`, background: "linear-gradient(90deg, #ef4444, #f59e0b)" }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>

      </div>
    </main>
  );
}