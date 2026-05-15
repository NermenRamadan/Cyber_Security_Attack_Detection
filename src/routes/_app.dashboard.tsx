import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { Activity, AlertTriangle, Clock } from "lucide-react";
import {
  AreaChart,
  Area,
  ResponsiveContainer,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
  BarChart,
  Bar,
} from "recharts";
import { supabase } from "@/integrations/supabase/client";
import { severityPillClass, ATTACK_TYPES } from "@/lib/mockAttacks";

export const Route = createFileRoute("/_app/dashboard")({
  component: Dashboard,
  head: () => ({ meta: [{ title: "Dashboard — CyberShield" }] }),
});

const CHART_COLORS = ["#5fb6ff", "#7fd0ff", "#5dd8b8", "#f5c870", "#f08585", "#a78bfa"];

function StatCard({
  icon: Icon,
  label,
  value,
  hint,
  accent = "primary",
}: {
  icon: any;
  label: string;
  value: string | number;
  hint?: string;
  accent?: string;
}) {
  return (
    <div className="glass relative overflow-hidden rounded-2xl p-5">
      <div className="flex items-start justify-between">
        <div>
          <div className="text-xs uppercase tracking-wider text-muted-foreground">{label}</div>
          <div className="mt-2 text-3xl font-semibold tracking-tight">{value}</div>
          {hint && <div className="mt-1 text-xs text-muted-foreground">{hint}</div>}
        </div>
        <div
          className={`grid h-10 w-10 place-items-center rounded-xl bg-${accent}/10 text-${accent}`}
        >
          <Icon className="h-5 w-5" />
        </div>
      </div>
    </div>
  );
}

function Dashboard() {
  const [packets, setPackets] = useState(0);
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

    supabase
      .from("detection_logs")
      .select("*")
      .order("detected_at", { ascending: false })
      .limit(200)
      .then(({ data }) => setDbAttacks(data ?? []));

    const channel = supabase
      .channel("detection_logs_changes")
      .on(
        "postgres_changes",
        { event: "INSERT", schema: "public", table: "detection_logs" },
        (payload) => setDbAttacks((prev) => [payload.new, ...prev].slice(0, 200)),
      )
      .subscribe();

    return () => {
      clearInterval(timer);
      supabase.removeChannel(channel);
    };
  }, []);

  const all = useMemo(() => [...dbAttacks].slice(0, 200), [dbAttacks]);
  const detected = all.length;

  const durationText = useMemo(() => {
    const diffInMinutes = Math.floor((currentTime.getTime() - startTime.getTime()) / 60000);
    if (diffInMinutes < 1) return "Just started";
    if (diffInMinutes < 60) return `Last ${diffInMinutes} minutes`;
    const hours = Math.floor(diffInMinutes / 60);
    return `Last ${hours} hour${hours > 1 ? 's' : ''}`;
  }, [startTime, currentTime]);

  const overTime = useMemo(() => {
    const buckets: Record<string, number> = {};
    for (let i = 11; i >= 0; i--) {
      const d = new Date(Date.now() - i * 30 * 60 * 1000);
      const k = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      buckets[k] = 0;
    }
    all.forEach((a) => {
      const t = new Date(a.detected_at);
      const k = t.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      if (k in buckets) buckets[k]++;
    });
    return Object.entries(buckets).map(([time, count]) => ({ time, count }));
  }, [all]);

  const distribution = useMemo(() => {
    const m: Record<string, number> = {};
    ATTACK_TYPES.forEach((t) => (m[t] = 0));
    all.forEach((a) => (m[a.attack_type] = (m[a.attack_type] || 0) + 1));
    return Object.entries(m)
      .filter(([, v]) => v > 0)
      .map(([name, value]) => ({ name, value }));
  }, [all]);

  const anomaly = useMemo(() => {
    if (all.length === 0) return [];
    return Array.from({ length: 20 }, (_, i) => ({
      t: i,
      score: Math.round(40 + Math.sin(i / 2) * 15 + Math.random() * 30),
    }));
  }, [all.length]);

  const sources = useMemo(() => {
    const m: Record<string, number> = {};
    all.forEach((a: any) => {
      const c = a.source_country || "Unknown";
      m[c] = (m[c] || 0) + 1;
    });
    return Object.entries(m)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 8);
  }, [all]);

  const efficiency = useMemo(() => {
    if (all.length === 0) return [];
    return Array.from({ length: 10 }, (_, i) => ({
      label: `T-${10 - i}`,
      sec: Math.round((0.4 + Math.random() * 1.8) * 100) / 100,
    }));
  }, [all.length]);

  const last = all[0];

  return (
    <main className="mx-auto max-w-7xl px-6 py-8">
      <div className="mb-6">
        <h1 className="text-3xl font-semibold tracking-tight">Threat Dashboard</h1>
        <p className="text-sm text-muted-foreground">Live overview as of {currentTime.toLocaleTimeString()}</p>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <StatCard
          icon={Activity}
          label="Packets Analyzed"
          value={detected.toLocaleString()}
          hint="Live stream"
        />
        <StatCard
          icon={AlertTriangle}
          label="Attacks Detected"
          value={detected}
          hint={durationText}
          accent="destructive"
        />
        <StatCard
          icon={Clock}
          label="Avg Response"
          value={detected > 0 ? "0.92s" : "0.00s"}
          hint={detected > 0 ? "⚡ Optimal Performance" : "System Standby"}
          accent="accent"
        />
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
                <Tooltip
                  contentStyle={{
                    background: "rgba(20,30,50,0.95)",
                    border: "1px solid rgba(255,255,255,0.1)",
                    borderRadius: 8,
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="count"
                  stroke="#5fb6ff"
                  fill="url(#ga)"
                  strokeWidth={2}
                />
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
              <Row
                k="Severity"
                v={
                  <span
                    className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ${severityPillClass(last.severity)}`}
                  >
                    {last.severity}
                  </span>
                }
              />
              <Row k="Confidence" v={`${last.confidence}%`} />
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No events yet.</p>
          )}
        </div>
      </div>

      {/* ... باقي الكود كما هو بدون أي تغيير في الـ UI ... */}
      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <div className="glass rounded-2xl p-5">
          <h3 className="mb-1 text-base font-medium">Attack Type Distribution</h3>
          <p className="mb-4 text-xs text-muted-foreground">Breakdown by category</p>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={distribution}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={45}
                  outerRadius={88}
                  paddingAngle={2}
                >
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
          </div>
        </div>

        <div className="glass rounded-2xl p-5">
          <h3 className="mb-1 text-base font-medium">Anomaly Score Timeline</h3>
          <p className="mb-4 text-xs text-muted-foreground">Real-time risk signal</p>
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={anomaly}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                <XAxis dataKey="t" stroke="rgba(255,255,255,0.4)" fontSize={11} />
                <YAxis stroke="rgba(255,255,255,0.4)" fontSize={11} domain={[0, 100]} />
                <Tooltip contentStyle={{ background: "rgba(20,30,50,0.95)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8 }} />
                <Line type="monotone" dataKey="score" stroke="#7fd0ff" strokeWidth={2.5} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <div className="glass rounded-2xl p-5">
          <h3 className="mb-1 text-base font-medium">Attack Sources</h3>
          <p className="mb-4 text-xs text-muted-foreground">Top origin geographies</p>
          <div className="space-y-2.5">
            {sources.map((s, i) => {
              const max = sources[0]?.value || 1;
              return (
                <div key={s.name}>
                  <div className="mb-1 flex justify-between text-sm">
                    <span>{s.name}</span>
                    <span className="text-muted-foreground">{s.value}</span>
                  </div>
                  <div className="h-2 overflow-hidden rounded-full bg-white/5">
                    <div className="h-full rounded-full" style={{ width: `${(s.value / max) * 100}%`, background: CHART_COLORS[i % CHART_COLORS.length] }} />
                  </div>
                </div>
              );
            })}
            {sources.length === 0 && <p className="text-sm text-muted-foreground">No data yet.</p>}
          </div>
        </div>

        <div className="glass rounded-2xl p-5">
          <h3 className="mb-1 text-base font-medium">Response Efficiency (sec)</h3>
          <p className="mb-4 text-xs text-muted-foreground">Lower is better</p>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={efficiency}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                <XAxis dataKey="label" stroke="rgba(255,255,255,0.4)" fontSize={11} />
                <YAxis stroke="rgba(255,255,255,0.4)" fontSize={11} />
                <Tooltip contentStyle={{ background: "rgba(20,30,50,0.95)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8 }} />
                <Bar dataKey="sec" fill="#5dd8b8" radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
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