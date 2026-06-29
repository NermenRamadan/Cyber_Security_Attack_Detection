import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { Activity, AlertTriangle, Clock } from "lucide-react";
import {
  AreaChart, Area, ResponsiveContainer, XAxis, YAxis, Tooltip,
  CartesianGrid, PieChart, Pie, Cell, LineChart, Line, BarChart, Bar,
} from "recharts";
import { severityPillClass, ATTACK_TYPES } from "@/lib/mockAttacks";

export const Route = createFileRoute("/_app/dashboard")({
  component: Dashboard,
  head: () => ({ meta: [{ title: "Dashboard – CyberShield" }] }),
});

const CHART_COLORS = ["#5fb6ff", "#7fd0ff", "#5dd8b8", "#f5c870", "#f08585", "#a78bfa"];

function StatCard({ icon: Icon, label, value, hint, accent = "primary" }: {
  icon: any; label: string; value: string | number; hint?: string; accent?: string;
}) {
  return (
    <div className="glass relative overflow-hidden rounded-2xl p-5">
      <div className="flex items-start justify-between">
        <div>
          <div className="text-xs uppercase tracking-wider text-muted-foreground">{label}</div>
          <div className="mt-2 text-3xl font-semibold tracking-tight">{value}</div>
          <div className="mt-1 text-xs text-muted-foreground">{hint}</div>
        </div>
        <div className={`grid h-10 w-10 place-items-center rounded-xl bg-${accent}/10 text-${accent}`}>
          <Icon className="h-5 w-5" />
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
    // 1️⃣ تحديث الوقت الحالي كل ثانية
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);

    // 2️⃣ دالة لجلب البيانات من الـ Local SQLite API
    const loadLocalLogs = async () => {
      try {
        const r = await fetch("http://127.0.0.1:8000/api/logs?limit=500");
        if (r.ok) {
          const data = await r.json();
          setDbAttacks(data ?? []);
        }
      } catch (err) {
        console.error("Error loading dashboard data from SQLite:", err);
      }
    };

    // جلب البيانات فوراً عند تحميل الصفحة
    loadLocalLogs();

    // عمل تحديث تلقائي (Polling) كل 3 ثوانٍ لمحاكاة الـ Real-time
    const dataInterval = setInterval(loadLocalLogs, 3000);

    return () => { 
      clearInterval(timer); 
      clearInterval(dataInterval);
    };
  }, []);

  const all = useMemo(() => [...dbAttacks].slice(0, 500), [dbAttacks]);

  const attacksOnly = useMemo(() => all.filter((r) => r.status !== "normal"), [all]);
  const detected = all.length;
  const attackCount = attacksOnly.length;

  const durationText = useMemo(() => {
    const diff = Math.floor((currentTime.getTime() - startTime.getTime()) / 60000);
    if (diff < 1) return "Just started";
    if (diff < 60) return `Last ${diff} minutes`;
    return `Last ${Math.floor(diff / 60)} hour${Math.floor(diff / 60) > 1 ? "s" : ""}`;
  }, [startTime, currentTime]);

  // ── Attacks Over Time ─────────────────────────────────────────
  const overTime = useMemo(() => {
    const buckets: Record<string, number> = {};
    for (let i = 11; i >= 0; i--) {
      const d = new Date(Date.now() - i * 30 * 60 * 1000);
      const k = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      buckets[k] = 0;
    }
    attacksOnly.forEach((a) => {
      const k = new Date(a.detected_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      if (k in buckets) buckets[k]++;
    });
    return Object.entries(buckets).map(([time, count]) => ({ time, count }));
  }, [attacksOnly]);

  // ── Attack Distribution ───────────────────────────────────────
  const distribution = useMemo(() => {
    const m: Record<string, number> = {};
    ATTACK_TYPES.forEach((t) => (m[t] = 0));
    attacksOnly.forEach((a) => (m[a.attack_type] = (m[a.attack_type] || 0) + 1));
    return Object.entries(m).filter(([, v]) => v > 0).map(([name, value]) => ({ name, value }));
  }, [attacksOnly]);

  // ── Anomaly Score — REAL DATA ─────────────────────────────────
  const anomaly = useMemo(() => {
    if (all.length === 0) return [];
    const BUCKETS = 20;
    const WINDOW_MIN = 10;
    const now = Date.now();
    return Array.from({ length: BUCKETS }, (_, i) => {
      const bucketEnd = now - (BUCKETS - 1 - i) * WINDOW_MIN * 60 * 1000;
      const bucketStart = bucketEnd - WINDOW_MIN * 60 * 1000;
      const inBucket = all.filter((r) => {
        const t = new Date(r.detected_at).getTime();
        return t >= bucketStart && t < bucketEnd;
      });
      const attacksInBucket = inBucket.filter((r) => r.status !== "normal").length;
      const total = inBucket.length;
      const score = total > 0 ? Math.round((attacksInBucket / total) * 100) : 0;
      const label = new Date(bucketEnd).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      return { t: label, score };
    });
  }, [all]);

  // ── Response Efficiency — REAL DATA ───────────────────────────
  const efficiency = useMemo(() => {
    if (attacksOnly.length === 0) return [];
    return attacksOnly.slice(0, 10).reverse().map((r, i) => ({
      label: `#${i + 1}`,
      confidence: r.confidence ? Math.round(r.confidence * 100) : 0,
      type: r.attack_type?.split("_")[0] || "Unknown",
    }));
  }, [attacksOnly]);

  // ── Attack Sources ────────────────────────────────────────────
  const sources = useMemo(() => {
    const m: Record<string, number> = {};
    attacksOnly.forEach((a: any) => {
      const c = a.source_ip || "Unknown";
      m[c] = (m[c] || 0) + 1;
    });
    return Object.entries(m).map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value).slice(0, 8);
  }, [attacksOnly]);

  // ── Avg confidence ────────────────────────────────────────────
  const avgConfidence = useMemo(() => {
    const withConf = attacksOnly.filter((r) => r.confidence != null);
    if (!withConf.length) return null;
    const avg = withConf.reduce((s, r) => s + r.confidence, 0) / withConf.length;
    return Math.round(avg * 100);
  }, [attacksOnly]);

  const last = attacksOnly[0];

  return (
    <main className="mx-auto max-w-7xl px-6 py-8">
      <div className="mb-6">
        <h1 className="text-3xl font-semibold tracking-tight">Threat Dashboard</h1>
        <p className="text-sm text-muted-foreground">Live overview as of {currentTime.toLocaleTimeString()}</p>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <StatCard icon={Activity} label="Total Logs" value={detected.toLocaleString()} hint="All traffic" />
        <StatCard icon={AlertTriangle} label="Attacks Detected" value={attackCount} hint={durationText} accent="destructive" />
        <StatCard icon={Clock} label="Avg Confidence"
          value={avgConfidence != null ? `${avgConfidence}%` : "—"}
          hint={avgConfidence != null ? "Model certainty on attacks" : "No attacks yet"}
          accent="accent" />
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <div className="glass rounded-2xl p-5 lg:col-span-2">
          <h3 className="mb-1 text-base font-medium">Attacks Over Time</h3>
          <p className="mb-4 text-xs text-muted-foreground">Detections per 30-minute window</p>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={overTime}>
                <defs>
                  <linearGradient id="ga" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#5fb6ff" stopOpacity={0.6} />
                    <stop offset="100%" stopColor="#5fb6ff" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                <XAxis dataKey="time" stroke="rgba(255,255,255,0.4)" fontSize={11} />
                <YAxis stroke="rgba(255,255,255,0.4)" fontSize={11} />
                <Tooltip contentStyle={{ background: "rgba(20,30,50,0.95)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8 }} />
                <Area type="monotone" dataKey="count" stroke="#5fb6ff" fill="url(#ga)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="glass rounded-2xl p-5">
          <h3 className="mb-1 text-base font-medium">Last Detection</h3>
          <p className="mb-4 text-xs text-muted-foreground">Most recent threat event</p>
          {last ? (
            <div className="space-y-3">
              <Row k="Type" v={<span className="font-medium">{last.attack_type}</span>} />
              <Row k="Source" v={<span className="font-mono text-sm">{last.source_ip}</span>} />
              <Row k="Time" v={new Date(last.detected_at).toLocaleTimeString()} />
              <Row k="Severity" v={
                <span className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ${severityPillClass(last.severity)}`}>
                  {last.severity}
                </span>} />
              <Row k="Confidence" v={last.confidence ? `${Math.round(last.confidence * 100)}%` : "—"} />
              {last.solution && (
                <div className="mt-2 rounded-lg bg-white/5 p-3 text-xs text-muted-foreground leading-relaxed">
                  💡 {last.solution}
                </div>
              )}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No attacks yet.</p>
          )}
        </div>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <div className="glass rounded-2xl p-5">
          <h3 className="mb-1 text-base font-medium">Attack Type Distribution</h3>
          <p className="mb-4 text-xs text-muted-foreground">Breakdown by category</p>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={distribution} dataKey="value" nameKey="name" innerRadius={45} outerRadius={88} paddingAngle={2}>
                  {distribution.map((_, i) => (
                    <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} stroke="rgba(10,15,30,0.6)" strokeWidth={1.5} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: "rgba(20,30,50,0.95)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8, color: "#fff" }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-3 grid grid-cols-2 gap-x-4 gap-y-2">
            {distribution.map((d, i) => (
              <div key={d.name} className="flex items-center justify-between gap-2 text-sm">
                <span className="flex items-center gap-2 text-foreground/90 truncate">
                  <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: CHART_COLORS[i % CHART_COLORS.length] }} />
                  <span className="truncate">{d.name}</span>
                </span>
                <span className="font-medium text-muted-foreground tabular-nums">{d.value}</span>
              </div>
            ))}
            {distribution.length === 0 && <p className="text-sm text-muted-foreground col-span-2">No attacks yet.</p>}
          </div>
        </div>

        <div className="glass rounded-2xl p-5">
          <h3 className="mb-1 text-base font-medium">Anomaly Score Timeline</h3>
          <p className="mb-4 text-xs text-muted-foreground">
            % of traffic classified as attack per 10-minute window
          </p>
          <div className="h-72">
            {anomaly.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={anomaly}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                  <XAxis dataKey="t" stroke="rgba(255,255,255,0.4)" fontSize={10} interval={4} />
                  <YAxis stroke="rgba(255,255,255,0.4)" fontSize={11} domain={[0, 100]}
                    tickFormatter={(v) => `${v}%`} />
                  <Tooltip
                    formatter={(v: any) => [`${v}%`, "Attack ratio"]}
                    contentStyle={{ background: "rgba(20,30,50,0.95)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8 }} />
                  <Line type="monotone" dataKey="score" stroke="#7fd0ff" strokeWidth={2.5} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
                No data yet — run monitor or upload CSV
              </div>
            )}
          </div>
        </div>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <div className="glass rounded-2xl p-5">
          <h3 className="mb-1 text-base font-medium">Top Attack Sources</h3>
          <p className="mb-4 text-xs text-muted-foreground">IPs with most detections</p>
          <div className="space-y-2.5">
            {sources.map((s, i) => {
              const max = sources[0]?.value || 1;
              return (
                <div key={s.name}>
                  <div className="mb-1 flex justify-between text-sm">
                    <span className="font-mono text-xs">{s.name}</span>
                    <span className="text-muted-foreground">{s.value}</span>
                  </div>
                  <div className="h-2 overflow-hidden rounded-full bg-white/5">
                    <div className="h-full rounded-full"
                      style={{ width: `${(s.value / max) * 100}%`, background: CHART_COLORS[i % CHART_COLORS.length] }} />
                  </div>
                </div>
              );
            })}
            {sources.length === 0 && <p className="text-sm text-muted-foreground">No attacks yet.</p>}
          </div>
        </div>

        <div className="glass rounded-2xl p-5">
          <h3 className="mb-1 text-base font-medium">Detection Confidence</h3>
          <p className="mb-4 text-xs text-muted-foreground">
            Model confidence % for last 10 attacks
          </p>
          <div className="h-64">
            {efficiency.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={efficiency}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                  <XAxis dataKey="label" stroke="rgba(255,255,255,0.4)" fontSize={11} />
                  <YAxis stroke="rgba(255,255,255,0.4)" fontSize={11} domain={[0, 100]}
                    tickFormatter={(v) => `${v}%`} />
                  <Tooltip
                    formatter={(v: any, _: any, p: any) => [`${v}% — ${p.payload.type}`, "Confidence"]}
                    contentStyle={{ background: "rgba(20,30,50,0.95)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8 }} />
                  <Bar dataKey="confidence" fill="#5dd8b8" radius={[6, 6, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
                No attacks detected yet
              </div>
            )}
          </div>
        </div>
      </div>
    </main>
  );
}

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between border-b border-white/5 pb-2 last:border-0">
      <span className="text-xs uppercase tracking-wider text-muted-foreground">{k}</span>
      <span className="text-sm">{v}</span>
    </div>
  );
}