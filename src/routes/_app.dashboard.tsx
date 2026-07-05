import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { Activity, AlertTriangle, Clock, Skull, ShieldCheck } from "lucide-react";
import {
  AreaChart, Area, ResponsiveContainer, XAxis, YAxis, Tooltip,
  CartesianGrid, PieChart, Pie, Cell, LineChart, Line as RLine, BarChart, Bar,
} from "recharts";
import { ComposableMap, Geographies, Geography, Marker, Line as MapLine } from "react-simple-maps";
import { severityPillClass, ATTACK_TYPES } from "@/lib/mockAttacks";

export const Route = createFileRoute("/_app/dashboard")({
  component: Dashboard,
  head: () => ({ meta: [{ title: "Dashboard – CyberShield" }] }),
});

// عنوان الـ Backend (API.py) — عدّليه لو شغال على بورت أو دومين مختلف
const API_URL = "http://localhost:8000";

// خريطة العالم (topojson) — ملف عام مجاني بيتحمّل مرة واحدة ويتخزن في الكاش
const GEO_URL = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";

// إحداثيات "المركز" اللي الهجمات بتوصله (سيرفرك) — عدّليها لموقعك الحقيقي
const HOME_COORDS: [number, number] = [31.2357, 30.0444]; // Cairo, Egypt

const CHART_COLORS = ["#5fb6ff", "#7fd0ff", "#5dd8b8", "#f5c870", "#f08585", "#a78bfa"];

function isPrivateIP(ip: string) {
  if (!ip || ip === "Unknown" || ip === "0.0.0.0" || ip === "127.0.0.1") return true;
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return true;
  const [a, b] = parts;
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a === 127;
}

function Sparkline({ data, color }: { data: number[]; color: string }) {
  const points = data.map((v, i) => ({ i, v }));
  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={points}>
        <Area type="monotone" dataKey="v" stroke={color} fill={color} fillOpacity={0.15} strokeWidth={1.5} isAnimationActive />
      </AreaChart>
    </ResponsiveContainer>
  );
}

function RadialGauge({ value, color }: { value: number; color: string }) {
  const r = 26;
  const c = 2 * Math.PI * r;
  const offset = c - (Math.max(0, Math.min(100, value)) / 100) * c;
  return (
    <svg viewBox="0 0 64 64" className="h-14 w-14 shrink-0 -rotate-90">
      <circle cx="32" cy="32" r={r} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="6" />
      <circle
        cx="32" cy="32" r={r} fill="none" stroke={color} strokeWidth="6" strokeLinecap="round"
        strokeDasharray={c} strokeDashoffset={offset}
        style={{ transition: "stroke-dashoffset 0.6s ease" }}
      />
    </svg>
  );
}

function StatCard({ icon: Icon, label, value, hint, accent = "primary", trend, critical }: {
  icon: any; label: string; value: string | number; hint?: string; accent?: string;
  trend?: number[]; critical?: boolean;
}) {
  return (
    <div className={`glass relative overflow-hidden rounded-2xl p-5 ${critical ? "border border-destructive/40 shadow-[0_0_24px_rgba(240,90,90,0.15)]" : ""}`}>
      <div className="flex items-start justify-between">
        <div>
          <div className="text-xs uppercase tracking-wider text-muted-foreground">{label}</div>
          <div className="mt-2 text-3xl font-semibold tracking-tight">{value}</div>
          {hint && <div className="mt-1 text-xs text-muted-foreground">{hint}</div>}
        </div>
        <div className={`grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-${accent}/10 text-${accent} ${critical ? "animate-pulse" : ""}`}>
          <Icon className="h-5 w-5" />
        </div>
      </div>
      {trend && trend.length > 1 && (
        <div className="mt-3 h-10 opacity-80">
          <Sparkline data={trend} color={critical ? "#f08585" : "#5fb6ff"} />
        </div>
      )}
    </div>
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

function Dashboard() {
  const navigate = useNavigate();
  const [dbAttacks, setDbAttacks] = useState<any[]>([]);
  const [currentTime, setCurrentTime] = useState<Date>(new Date());
  const [geoCache, setGeoCache] = useState<Record<string, { lat: number; lon: number; country?: string }>>({});

  const startTime = useMemo(() => {
    const saved = localStorage.getItem("monitoring_start_time");
    if (saved) return new Date(saved);
    const now = new Date();
    localStorage.setItem("monitoring_start_time", now.toISOString());
    return now;
  }, []);

  // ── جلب اللوجز بتاعة اليوزر الحالي بس من الـ API (بدل Supabase) ──────
  useEffect(() => {
    const userId = localStorage.getItem("user_id");
    if (!userId) {
      navigate({ to: "/login" });
      return;
    }

    let cancelled = false;
    const fetchLogs = async () => {
      try {
        const res = await fetch(`${API_URL}/api/logs?user_id=${userId}&limit=500`);
        if (!res.ok) return;
        const data = await res.json();
        if (!cancelled) setDbAttacks(data);
      } catch {
        // الـ API مش شغالة دلوقتي — بنسيب آخر بيانات معروفة زي ما هي
      }
    };

    fetchLogs();
    const poll = setInterval(fetchLogs, 4000);
    const clock = setInterval(() => setCurrentTime(new Date()), 1000);

    return () => { cancelled = true; clearInterval(poll); clearInterval(clock); };
  }, [navigate]);

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

  // ── Anomaly Score ──────────────────────────────────────────────
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

  // ── Security Score (100 - متوسط نسبة الهجمات في آخر فترة) ─────
  const securityScore = useMemo(() => {
    if (anomaly.length === 0) return 100;
    const recent = anomaly.slice(-6);
    const avgRisk = recent.reduce((s, r) => s + r.score, 0) / recent.length;
    return Math.max(0, Math.round(100 - avgRisk));
  }, [anomaly]);

  const scoreLabel =
    securityScore >= 90 ? "Excellent" : securityScore >= 75 ? "Good" : securityScore >= 50 ? "Fair" : "At Risk";
  const scoreColor = securityScore >= 75 ? "#5dd8b8" : securityScore >= 50 ? "#f5c870" : "#f08585";

  // ── Response Efficiency ────────────────────────────────────────
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
      .sort((a, b) => b.value - a.value).slice(0, 12);
  }, [attacksOnly]);

  // ── Geolocation للـ IPs العامة بس (الـ private/internal مالهاش لازمة) ──
  useEffect(() => {
    const toFetch = sources
      .map((s) => s.name)
      .filter((ip) => !isPrivateIP(ip) && !(ip in geoCache))
      .slice(0, 10);
    if (toFetch.length === 0) return;

    let cancelled = false;
    (async () => {
      for (const ip of toFetch) {
        try {
          const res = await fetch(`https://ipapi.co/${ip}/json/`);
          const data = await res.json();
          if (!cancelled && data && data.latitude && data.longitude) {
            setGeoCache((prev) => ({
              ...prev,
              [ip]: { lat: data.latitude, lon: data.longitude, country: data.country_name },
            }));
          }
        } catch {
          // rate-limited أو IP مش موجود على ipapi.co — بنتجاهله
        }
      }
    })();

    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sources]);

  const mappedAttackers = useMemo(
    () => sources.filter((s) => geoCache[s.name]).map((s) => ({ ...s, ...geoCache[s.name] })),
    [sources, geoCache]
  );
  const internalCount = useMemo(
    () => sources.filter((s) => isPrivateIP(s.name)).reduce((sum, s) => sum + s.value, 0),
    [sources]
  );

  // ── Avg confidence ────────────────────────────────────────────
  const avgConfidence = useMemo(() => {
    const withConf = attacksOnly.filter((r) => r.confidence != null);
    if (!withConf.length) return null;
    const avg = withConf.reduce((s, r) => s + r.confidence, 0) / withConf.length;
    return Math.round(avg * 100);
  }, [attacksOnly]);

  const last = attacksOnly[0] ?? null;
  const isSevereAlert = last && (last.severity === "Critical" || last.severity === "High");
  const overTimeCounts = useMemo(() => overTime.map((o) => o.count), [overTime]);

  return (
    <main className="mx-auto max-w-7xl px-6 py-8">
      <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-3xl font-semibold tracking-tight">Threat Dashboard</h1>
          <p className="text-sm text-muted-foreground">Live overview as of {currentTime.toLocaleTimeString()}</p>
        </div>
        <div className="flex items-center gap-2 rounded-full glass px-4 py-1.5 text-xs uppercase tracking-widest text-muted-foreground">
          <span className={`h-2 w-2 rounded-full ${attackCount > 0 ? "animate-pulse bg-destructive" : "animate-pulse bg-success"}`} />
          {attackCount > 0 ? "Threats active" : "Live monitoring"}
        </div>
      </div>

      {/* stat cards */}
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatCard icon={Activity} label="Total Alerts" value={detected.toLocaleString()} hint={durationText} accent="primary" trend={overTimeCounts} />
        <StatCard icon={AlertTriangle} label="Active Attacks" value={attackCount} hint={durationText} accent="destructive" trend={overTimeCounts} critical={attackCount > 0} />
        <StatCard icon={ShieldCheck} label="Avg Confidence" value={avgConfidence != null ? `${avgConfidence}%` : "—"} hint={avgConfidence != null ? "Model certainty on attacks" : "No attacks yet"} accent="accent" />
        <div className="glass relative flex items-center justify-between overflow-hidden rounded-2xl p-5">
          <div>
            <div className="text-xs uppercase tracking-wider text-muted-foreground">Security Score</div>
            <div className="mt-2 text-3xl font-semibold tracking-tight">{securityScore}%</div>
            <div className="mt-1 text-xs text-muted-foreground">{scoreLabel}</div>
          </div>
          <RadialGauge value={securityScore} color={scoreColor} />
        </div>
      </div>

      {/* live attack map + critical alert */}
      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <div className="glass rounded-2xl p-5 lg:col-span-2">
          <div className="mb-3 flex items-center justify-between">
            <div>
              <h3 className="text-base font-medium">Live Attack Map</h3>
              <p className="text-xs text-muted-foreground">Origin of detected attack traffic (public IPs only)</p>
            </div>
            {internalCount > 0 && (
              <span className="text-xs text-muted-foreground">+{internalCount} from internal/private IPs</span>
            )}
          </div>
          <div className="relative h-72 overflow-hidden rounded-xl bg-[#060b18]">
            <ComposableMap projectionConfig={{ scale: 140 }} width={800} height={380} style={{ width: "100%", height: "100%" }}>
              <Geographies geography={GEO_URL}>
                {({ geographies }) =>
                  geographies.map((geo) => (
                    <Geography
                      key={geo.rsmKey} geography={geo}
                      fill="rgba(95,182,255,0.08)" stroke="rgba(95,182,255,0.25)" strokeWidth={0.5}
                    />
                  ))
                }
              </Geographies>

              {mappedAttackers.map((a) => (
                <MapLine
                  key={`line-${a.name}`} from={[a.lon, a.lat]} to={HOME_COORDS}
                  stroke="rgba(240,90,90,0.45)" strokeWidth={1} strokeDasharray="3 3"
                />
              ))}

              <Marker coordinates={HOME_COORDS}>
                <circle r={5} fill="#5fb6ff" stroke="#fff" strokeWidth={1} />
              </Marker>

              {mappedAttackers.map((a) => (
                <Marker key={a.name} coordinates={[a.lon, a.lat]}>
                  <circle r={4 + Math.min(a.value, 8)} fill="rgba(240,90,90,0.35)" className="animate-pulse" />
                  <circle r={3} fill="#f08585" />
                </Marker>
              ))}
            </ComposableMap>

            {mappedAttackers.length === 0 && (
              <div className="absolute inset-0 flex items-center justify-center px-6 text-center text-sm text-muted-foreground">
                Waiting for attacks from public IPs to plot on the map…
              </div>
            )}
          </div>
        </div>

        {isSevereAlert ? (
          <div className="glass relative overflow-hidden rounded-2xl border border-destructive/40 p-5 shadow-[0_0_28px_rgba(240,90,90,0.18)]">
            <div className="mb-4 flex items-center justify-between">
              <h3 className="text-base font-semibold text-destructive">Critical Attack Alert</h3>
              <span className="rounded-full bg-destructive px-2.5 py-1 text-xs font-semibold text-white">{last.severity}</span>
            </div>
            <div className="flex items-center gap-4">
              <div className="grid h-16 w-16 shrink-0 animate-pulse place-items-center rounded-full bg-destructive/15 text-destructive">
                <Skull className="h-8 w-8" />
              </div>
              <div className="flex-1 space-y-1.5">
                <Row k="Type" v={<span className="font-medium">{last.attack_type}</span>} />
                <Row k="Source" v={<span className="font-mono text-sm">{last.source_ip}</span>} />
                <Row k="Time" v={new Date(last.detected_at).toLocaleTimeString()} />
              </div>
            </div>
            {last.solution && (
              <div className="mt-4 rounded-lg bg-white/5 p-3 text-xs leading-relaxed text-muted-foreground">
                💡 {last.solution}
              </div>
            )}
          </div>
        ) : last ? (
          <div className="glass rounded-2xl p-5">
            <h3 className="mb-4 text-base font-medium">Last Detection</h3>
            <div className="space-y-3">
              <Row k="Type" v={<span className="font-medium">{last.attack_type}</span>} />
              <Row k="Source" v={<span className="font-mono text-sm">{last.source_ip}</span>} />
              <Row k="Time" v={new Date(last.detected_at).toLocaleTimeString()} />
              <Row k="Severity" v={
                <span className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ${severityPillClass(last.severity)}`}>
                  {last.severity}
                </span>} />
              <Row k="Confidence" v={last.confidence ? `${Math.round(last.confidence * 100)}%` : "—"} />
            </div>
          </div>
        ) : (
          <div className="glass flex flex-col items-center justify-center rounded-2xl p-5 text-center">
            <div className="grid h-16 w-16 place-items-center rounded-full bg-success/10 text-success">
              <ShieldCheck className="h-8 w-8" />
            </div>
            <h3 className="mt-3 text-base font-semibold">All Systems Secure</h3>
            <p className="mt-1 text-xs text-muted-foreground">No threats detected yet</p>
          </div>
        )}
      </div>

      {/* distribution + attacks over time */}
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
                <span className="flex items-center gap-2 truncate text-foreground/90">
                  <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ background: CHART_COLORS[i % CHART_COLORS.length] }} />
                  <span className="truncate">{d.name}</span>
                </span>
                <span className="font-medium text-muted-foreground tabular-nums">{d.value}</span>
              </div>
            ))}
            {distribution.length === 0 && <p className="col-span-2 text-sm text-muted-foreground">No attacks yet.</p>}
          </div>
        </div>

        <div className="glass rounded-2xl p-5">
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
      </div>

      {/* recent alerts + anomaly timeline */}
      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <div className="glass rounded-2xl p-5">
          <h3 className="mb-4 text-base font-medium">Recent Alerts</h3>
          <div className="space-y-3">
            {all.slice(0, 8).map((r) => (
              <div key={r.id} className="flex items-center justify-between gap-3 border-b border-white/5 pb-2 last:border-0">
                <div className="flex min-w-0 items-center gap-3">
                  <span className="shrink-0 font-mono text-xs text-muted-foreground">
                    {new Date(r.detected_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                  </span>
                  <span className="truncate text-sm">{r.status === "normal" ? "Normal traffic logged" : r.attack_type}</span>
                </div>
                <span className={`shrink-0 inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-semibold ${severityPillClass(r.severity)}`}>
                  {r.severity}
                </span>
              </div>
            ))}
            {all.length === 0 && <p className="text-sm text-muted-foreground">No detections yet.</p>}
          </div>
        </div>

        <div className="glass rounded-2xl p-5">
          <h3 className="mb-1 text-base font-medium">Anomaly Score Timeline</h3>
          <p className="mb-4 text-xs text-muted-foreground">% of traffic classified as attack per 10-minute window</p>
          <div className="h-64">
            {anomaly.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={anomaly}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                  <XAxis dataKey="t" stroke="rgba(255,255,255,0.4)" fontSize={10} interval={4} />
                  <YAxis stroke="rgba(255,255,255,0.4)" fontSize={11} domain={[0, 100]} tickFormatter={(v) => `${v}%`} />
                  <Tooltip
                    formatter={(v: any) => [`${v}%`, "Attack ratio"]}
                    contentStyle={{ background: "rgba(20,30,50,0.95)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8 }} />
                  <RLine type="monotone" dataKey="score" stroke="#7fd0ff" strokeWidth={2.5} dot={false} />
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

      {/* sources + confidence */}
      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <div className="glass rounded-2xl p-5">
          <h3 className="mb-1 text-base font-medium">Top Attack Sources</h3>
          <p className="mb-4 text-xs text-muted-foreground">IPs with most detections</p>
          <div className="space-y-2.5">
            {sources.slice(0, 8).map((s, i) => {
              const max = sources[0]?.value || 1;
              return (
                <div key={s.name}>
                  <div className="mb-1 flex justify-between text-sm">
                    <span className="font-mono text-xs">{s.name}</span>
                    <span className="text-muted-foreground">{s.value}</span>
                  </div>
                  <div className="h-2 overflow-hidden rounded-full bg-white/5">
                    <div className="h-full rounded-full" style={{ width: `${(s.value / max) * 100}%`, background: CHART_COLORS[i % CHART_COLORS.length] }} />
                  </div>
                </div>
              );
            })}
            {sources.length === 0 && <p className="text-sm text-muted-foreground">No attacks yet.</p>}
          </div>
        </div>

        <div className="glass rounded-2xl p-5">
          <h3 className="mb-1 text-base font-medium">Detection Confidence</h3>
          <p className="mb-4 text-xs text-muted-foreground">Model confidence % for last 10 attacks</p>
          <div className="h-64">
            {efficiency.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={efficiency}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                  <XAxis dataKey="label" stroke="rgba(255,255,255,0.4)" fontSize={11} />
                  <YAxis stroke="rgba(255,255,255,0.4)" fontSize={11} domain={[0, 100]} tickFormatter={(v) => `${v}%`} />
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
