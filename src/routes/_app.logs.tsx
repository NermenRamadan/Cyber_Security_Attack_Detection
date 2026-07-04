import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { severityPillClass } from "@/lib/mockAttacks";
import { Trash2 } from "lucide-react";
import { toast } from "sonner";

export const Route = createFileRoute("/_app/logs")({
  component: Logs,
  head: () => ({ meta: [{ title: "Logs — CyberShield" }] }),
});

function Logs() {
  const [rows, setRows] = useState<any[]>([]);
  const [filter, setFilter] = useState("");

  // 1️⃣ قراءة الـ Logs وترتيبها من الأحدث للأقدم
  const load = async () => {
    let local: any[] = [];
    try {
      const raw = localStorage.getItem("cs_logs");
      local = raw ? JSON.parse(raw) : [];
    } catch {}

    try {
      const r = await fetch("http://127.0.0.1:8000/api/logs?limit=500");
      if (r.ok) {
        const data = await r.json();
        const merged = [...local, ...(data ?? [])]
          .sort((a, b) => new Date(b.detected_at).getTime() - new Date(a.detected_at).getTime());
        setRows(merged);
      } else {
        setRows(local);
      }
    } catch (err) {
      console.error("Error fetching logs from local API:", err);
      setRows(local);
    }
  };

  useEffect(() => { load(); }, []);

  // 2️⃣ دالة مسح السجلات من الـ SQLite والـ LocalStorage
  const clear = async () => {
    try { localStorage.removeItem("cs_logs"); } catch {}
    
    try {
      const r = await fetch("http://127.0.0.1:8000/api/logs", {
        method: "DELETE",
      });
      
      if (r.ok) {
        setRows([]);
        toast.success("All logs cleared successfully");
      } else {
        toast.error("Failed to clear logs from server");
      }
    } catch (err) {
      console.error("Error clearing logs:", err);
      toast.error("Could not connect to the local API server");
    }
  };

  const filtered = rows.filter((r) =>
    !filter || 
    (r.attack_type && r.attack_type.toLowerCase().includes(filter.toLowerCase())) ||
    (r.source_ip && r.source_ip.includes(filter)) || 
    (r.severity && r.severity.toLowerCase().includes(filter.toLowerCase()))
  );

  return (
    <main className="mx-auto max-w-7xl px-6 py-8">
      <div className="mb-6 flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-3xl font-semibold tracking-tight">Detection Logs</h1>
          <p className="text-sm text-muted-foreground">{rows.length} events stored in SQLite database</p>
        </div>
        <div className="flex items-center gap-3">
          <input
            value={filter} onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter by IP, type, severity..."
            className="rounded-lg border border-white/10 bg-white/5 px-4 py-2 text-sm outline-none focus:border-cyan-500/50"
          />
          <button onClick={clear}
            className="flex items-center gap-2 rounded-lg glass px-4 py-2 text-sm hover:bg-red-500/20 hover:text-red-400 transition-colors">
            <Trash2 className="h-4 w-4" /> Clear Logs
          </button>
        </div>
      </div>

      <div className="glass-strong overflow-hidden rounded-2xl border border-white/5">
        <div className="overflow-x-auto">
          <table className="min-w-full text-[15px]">
            <thead className="border-b border-white/10 bg-white/[0.04] text-left text-xs font-semibold uppercase tracking-[0.12em] text-muted-foreground">
              <tr>
                <th className="px-5 py-4">Time</th>
                <th className="px-5 py-4">Source IP</th>
                <th className="px-5 py-4">Status</th>
                <th className="px-5 py-4">Attack Type</th>
                <th className="px-5 py-4">Protocol</th>
                <th className="px-5 py-4">Severity</th>
                <th className="px-5 py-4">Confidence</th>
                <th className="px-5 py-4">Solution</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-5 py-20 text-center text-muted-foreground">
                    No logs found. Run the monitor interface or process a dataset to populate.
                  </td>
                </tr>
              )}
              {filtered.map((r, i) => (
                <tr key={r.id || i} className="border-b border-white/5 last:border-0 transition-colors hover:bg-white/[0.04]">
                  <td className="whitespace-nowrap px-5 py-4 text-muted-foreground tabular-nums text-xs">
                    {r.detected_at ? new Date(r.detected_at).toLocaleString() : "—"}
                  </td>
                  <td className="px-5 py-4 font-mono text-sm text-cyan-400">{r.source_ip || "—"}</td>
                  <td className="px-5 py-4">
                    <span className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-medium ring-1 ${
                      r.status === "normal" 
                        ? "bg-emerald-500/15 text-emerald-400 ring-emerald-500/30" 
                        : r.status === "monitored"
                        ? "bg-cyan-500/15 text-cyan-400 ring-cyan-500/30"
                        : "bg-red-500/15 text-red-400 ring-red-500/30"
                    }`}>
                      {r.status || "detected"}
                    </span>
                  </td>
                  <td className="px-5 py-4 font-medium">{r.attack_type || "—"}</td>
                  <td className="px-5 py-4 text-muted-foreground">{r.protocol || "—"}</td>
                  <td className="px-5 py-4">
                    <span className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ${severityPillClass(r.severity)}`}>
                      {r.severity || "Low"}
                    </span>
                  </td>
                  <td className="px-5 py-4 text-muted-foreground tabular-nums font-mono">
                    {r.confidence 
                      ? `${Math.round(Number(r.confidence) * (Number(r.confidence) <= 1 ? 100 : 1))}%` 
                      : "—"}
                  </td>
                  <td className="px-5 py-4 text-sm text-muted-foreground max-w-md truncate">{r.solution || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </main>
  );
}