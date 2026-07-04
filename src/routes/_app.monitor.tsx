import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import { Play, Square, Upload, X, FileText, Download } from "lucide-react";
import { toast } from "sonner";
import { severityPillClass, type Attack } from "@/lib/mockAttacks";

export const Route = createFileRoute("/_app/monitor")({
  component: Monitor,
  head: () => ({ meta: [{ title: "Monitor – CyberShield" }] }),
});

const API_URL = "http://127.0.0.1:8000";

// ── helpers ──────────────────────────────────────────────────────
function parseCSV(text: string): Record<string, string>[] {
  const lines = text.trim().split("\n");
  if (lines.length < 2) return [];
  const headers = lines[0].split(",").map((h) => h.trim().replace(/"/g, ""));
  return lines.slice(1).map((line) => {
    const values: string[] = [];
    let cur = "", inQ = false;
    for (const ch of line) {
      if (ch === '"') { inQ = !inQ; continue; }
      if (ch === "," && !inQ) { values.push(cur.trim()); cur = ""; continue; }
      cur += ch;
    }
    values.push(cur.trim());
    const row: Record<string, string> = {};
    headers.forEach((h, i) => (row[h] = values[i] ?? ""));
    return row;
  });
}

function exportCSV(rows: any[]) {
  if (!rows.length) return;
  const headers = ["detected_at", "source_ip", "attack_type", "severity", "confidence", "protocol", "solution", "status"];
  const lines = [
    headers.join(","),
    ...rows.map((r) =>
      headers.map((h) => `"${String(r[h] ?? "").replace(/"/g, '""')}"`).join(",")
    ),
  ];
  const blob = new Blob([lines.join("\n")], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = `cybershield_results_${Date.now()}.csv`;
  a.click(); URL.revokeObjectURL(url);
}

// ── component ─────────────────────────────────────────────────────
function Monitor() {
  const navigate = useNavigate();
  const [running, setRunning] = useState(false);
  const [liveRows, setLiveRows] = useState<Attack[]>([]);
  const [csvFile, setCsvFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [uploadTotal, setUploadTotal] = useState(0);
  const [csvResults, setCsvResults] = useState<any[]>([]);
  const [summary, setSummary] = useState<{ total: number, attacks: number, normal: number } | null>(null);
  const channelRef = useRef<any>(null); 
  const fileInputRef = useRef<HTMLInputElement>(null);
  const abortRef = useRef(false);

  useEffect(() => {
    return () => {
      if (channelRef.current) clearInterval(channelRef.current);
    };
  }, []);

  // ── live monitor (Polling SQLite API) ───────────────────────────
  const start = () => {
    if (running) return;
    setRunning(true);
    toast.success("Real-time monitoring started");

    const fetchLogs = async () => {
      try {
        const r = await fetch(`${API_URL}/api/logs?limit=200`);
        if (r.ok) {
          const data = await r.json();
          setLiveRows(data ?? []);
        }
      } catch (err) {
        console.error("Polling error:", err);
      }
    };

    fetchLogs();
    const poll = setInterval(fetchLogs, 2000);
    channelRef.current = poll;
  };

  const stop = () => {
    if (channelRef.current) clearInterval(channelRef.current);
    channelRef.current = null;
    setRunning(false);
    localStorage.removeItem("monitoring_start_time");
    toast.success("Monitoring stopped");
    setTimeout(() => navigate({ to: "/logs" }), 600);
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (!file.name.endsWith(".csv")) { toast.error("Please upload a CSV file"); return; }
    setCsvFile(file);
    setCsvResults([]);
    setSummary(null);
    toast.success(`Selected: ${file.name}`);
  };

  const handleUpload = async () => {
    if (!csvFile) return;
    setUploading(true);
    abortRef.current = false;
    setUploadProgress(0);
    setCsvResults([]);
    setSummary(null);

    try {
      const text = await csvFile.text();
      const rows = parseCSV(text);
      if (rows.length === 0) { toast.error("CSV is empty or invalid"); setUploading(false); return; }

      const isWireshark = "IP Source" in rows[0] || "IP Destination" in rows[0];
      const endpoint = isWireshark ? "/predict/wireshark-row" : "/predict/csv-row";
      toast.success(`Detected format: ${isWireshark ? "Wireshark" : "Generic"} — processing ${rows.length} rows...`);

      setUploadTotal(rows.length);
      let processed = 0, attacks = 0, normal = 0;
      const results: any[] = [];

      for (const row of rows) {
        if (abortRef.current) { toast.warning("Cancelled"); break; }
        try {
          // 1. تمرير السطر الحالي على الموديل للحصول على التوقع الذكي
          const res = await fetch(`${API_URL}${endpoint}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(row),
          });
          
          if (res.ok) {
            const result = await res.json();
            const conf = result.confidence != null ? parseFloat((result.confidence * 100).toFixed(1)) : null;
            
            const entry = {
              detected_at: new Date().toISOString(),
              source_ip: row["IP Source"] || row["source_ip"] || "—",
              attack_type: result.attack_type,
              severity: result.severity,
              confidence: conf,
              protocol: row["Protocol"] || "TCP",
              solution: result.solution || "",
              status: result.is_attack ? "detected" : "normal",
              true_label: row["label"] || "",
            };
            
            results.push(entry);
            if (result.is_attack) attacks++; else normal++;

            // ── التعديل الجوهري: مزامنة وحفظ البيانات المكتشفة فوراً في الـ SQLite ──
            await fetch(`${API_URL}/api/logs`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                source_ip: entry.source_ip,
                attack_type: entry.attack_type,
                severity: entry.severity,
                confidence: entry.confidence,
                protocol: entry.protocol,
                solution: entry.solution,
                status: entry.status,
                detected_at: entry.detected_at
              }),
            }).catch(err => console.error("Failed to sync log to SQLite:", err));
          }
        } catch { /* skip */ }
        processed++;
        setUploadProgress(processed);
        if (processed % 20 === 0) await new Promise((r) => setTimeout(r, 30));
      }

      setCsvResults(results);
      setSummary({ total: processed, attacks, normal });
      toast.success(`Done! ${attacks} attacks found and synced to SQLite out of ${processed} rows`);
    } catch {
      toast.error("Error reading file");
    } finally {
      setUploading(false); setUploadProgress(0); setUploadTotal(0);
    }
  };

  const progressPercent = uploadTotal > 0 ? Math.round((uploadProgress / uploadTotal) * 100) : 0;
  const displayRows = csvResults.length > 0 ? csvResults : liveRows;

  return (
    <main className="mx-auto max-w-7xl px-6 py-8">
      
      <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="text-sm text-muted-foreground font-mono">
          MONITORING INTERFACE & DATASET ANALYSIS
        </div>
        <div className="flex items-center gap-3">
          {!running ? (
            <button onClick={start}
              className="flex items-center gap-2 rounded-xl px-5 py-2 text-sm font-medium text-white transition-all duration-200 hover:opacity-90 shadow-[0_0_15px_rgba(0,240,255,0.15)]"
              style={{ background: "linear-gradient(90deg, #00f0ff 0%, #0072ff 100%)", color: "#050811" }}>
              <Play className="h-4 w-4" /> Start Live Monitor
            </button>
          ) : (
            <button onClick={stop}
              className="flex items-center gap-2 rounded-xl bg-red-600/90 hover:bg-red-600 px-5 py-2 text-sm font-medium text-white transition-all duration-200 shadow-[0_0_15px_rgba(239,68,68,0.2)]">
              <Square className="h-4 w-4" /> Stop Live Monitor
            </button>
          )}
        </div>
      </div>

      {/* ── CSV upload card ── */}
      <div className="mb-6 glass rounded-2xl p-5">
        <div className="flex items-center justify-between mb-1">
          <h2 className="text-base font-medium">Upload CSV Dataset</h2>
          {csvResults.length > 0 && (
            <button onClick={() => exportCSV(csvResults)}
              className="flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium bg-white/10 hover:bg-white/20 transition-colors">
              <Download className="h-3.5 w-3.5" /> Export Results
            </button>
          )}
        </div>
        <p className="text-xs text-muted-foreground mb-4">
          Supports Wireshark exports — auto-detects columns and maps to model features
        </p>

        <div className="flex flex-col gap-4 sm:flex-row sm:items-end">
          <div className="flex-1">
            {!csvFile ? (
              <label className="flex cursor-pointer flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed border-white/20 px-6 py-8 text-center transition-colors hover:border-cyan-500/50 hover:bg-white/[0.02]"
                onClick={() => fileInputRef.current?.click()}>
                <Upload className="h-8 w-8 text-muted-foreground" />
                <span className="text-sm text-muted-foreground">
                  Click to select <span className="text-foreground font-medium">.csv</span> file
                </span>
                <span className="text-xs text-muted-foreground">Wireshark exports supported</span>
                <input ref={fileInputRef} type="file" accept=".csv" className="hidden" onChange={handleFileChange} />
              </label>
            ) : (
              <div className="flex items-center gap-3 rounded-xl border border-white/10 bg-white/[0.03] px-4 py-3">
                <FileText className="h-5 w-5 text-cyan-400 shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium truncate">{csvFile.name}</p>
                  <p className="text-xs text-muted-foreground">{(csvFile.size / 1024 / 1024).toFixed(2)} MB</p>
                </div>
                {!uploading && (
                  <button onClick={() => { setCsvFile(null); setCsvResults([]); setSummary(null); if (fileInputRef.current) fileInputRef.current.value = ""; }}
                    className="text-muted-foreground hover:text-foreground">
                    <X className="h-4 w-4" />
                  </button>
                )}
              </div>
            )}
          </div>

          <div className="flex gap-2">
            {!uploading ? (
              <button onClick={handleUpload} disabled={!csvFile}
                className="flex items-center gap-2 rounded-xl px-5 py-2.5 text-sm font-medium text-white transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                style={{ background: csvFile ? "linear-gradient(90deg, #00f0ff 0%, #0072ff 100%)" : "rgba(255,255,255,0.1)", color: csvFile ? "#050811" : "inherit" }}>
                <Upload className="h-4 w-4" /> Run Analysis
              </button>
            ) : (
              <button onClick={() => abortRef.current = true}
                className="flex items-center gap-2 rounded-xl bg-red-600/80 px-5 py-2.5 text-sm font-medium text-white transition-transform hover:scale-105">
                <X className="h-4 w-4" /> Cancel
              </button>
            )}
          </div>
        </div>

        {/* progress */}
        {uploading && (
          <div className="mt-4">
            <div className="mb-2 flex justify-between text-xs text-muted-foreground">
              <span>Analyzing & saving rows...</span>
              <span>{uploadProgress} / {uploadTotal} ({progressPercent}%)</span>
            </div>
            <div className="h-2 overflow-hidden rounded-full bg-white/10">
              <div className="h-full rounded-full transition-all duration-300"
                style={{ width: `${progressPercent}%`, background: "linear-gradient(90deg, #00f0ff 0%, #0072ff 100%)" }} />
            </div>
          </div>
        )}

        {/* summary cards */}
        {summary && (
          <div className="mt-4 grid grid-cols-3 gap-3">
            <div className="rounded-xl bg-white/5 px-4 py-3 text-center">
              <p className="text-2xl font-semibold font-mono">{summary.total}</p>
              <p className="text-xs text-muted-foreground mt-1">Total Rows</p>
            </div>
            <div className="rounded-xl bg-red-500/10 px-4 py-3 text-center">
              <p className="text-2xl font-semibold text-red-500 font-mono">{summary.attacks}</p>
              <p className="text-xs text-muted-foreground mt-1">Attacks Found</p>
            </div>
            <div className="rounded-xl bg-cyan-500/10 px-4 py-3 text-center">
              <p className="text-2xl font-semibold text-cyan-400 font-mono">{summary.normal}</p>
              <p className="text-xs text-muted-foreground mt-1">Normal Traffic</p>
            </div>
          </div>
        )}
      </div>

      {/* live indicator */}
      {running && (
        <div className="mb-4 flex items-center gap-3 glass rounded-xl px-4 py-3 text-sm border border-emerald-500/20">
          <span className="relative flex h-3 w-3">
            <span className="absolute inset-0 rounded-full bg-emerald-500 animate-ping opacity-75" />
            <span className="relative h-3 w-3 rounded-full bg-emerald-500" />
          </span>
          <span className="text-muted-foreground font-mono text-xs">Capturing packets from SQLite — API live sync active.</span>
        </div>
      )}

      {/* results table */}
      <div className="glass-strong overflow-hidden rounded-2xl border border-white/5">
        {csvResults.length > 0 && (
          <div className="px-5 py-3 border-b border-white/10 text-xs text-muted-foreground font-mono">
            Showing CSV analysis results — {csvResults.length} rows
          </div>
        )}
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
                {csvResults.length > 0 && <th className="px-5 py-4">True Label</th>}
                <th className="px-5 py-4">Solution</th>
              </tr>
            </thead>
            <tbody>
              {displayRows.length === 0 && (
                <tr>
                  <td colSpan={9} className="px-5 py-20 text-center text-muted-foreground">
                    Press <span className="text-foreground font-medium">Start Live Monitor</span> or upload a CSV to begin.
                  </td>
                </tr>
              )}
              {displayRows.map((r: any, i) => (
                <tr key={r.id || i}
                  className="border-b border-white/5 last:border-0 transition-colors hover:bg-white/[0.04]">
                  <td className="whitespace-nowrap px-5 py-4 text-muted-foreground tabular-nums text-xs">
                    {new Date(r.detected_at).toLocaleTimeString()}
                  </td>
                  <td className="px-5 py-4 font-mono text-sm text-cyan-400">{r.source_ip}</td>
                  <td className="px-5 py-4">
                    <span className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-medium ring-1 ${
                      r.status === "normal"
                        ? "bg-emerald-500/15 text-emerald-400 ring-emerald-500/30"
                        : "bg-red-500/15 text-red-400 ring-red-500/30"
                    }`}>{r.status}</span>
                  </td>
                  <td className="px-5 py-4 font-medium">{r.attack_type}</td>
                  <td className="px-5 py-4 text-muted-foreground">{r.protocol}</td>
                  <td className="px-5 py-4">
                    <span className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ${severityPillClass(r.severity)}`}>
                      {r.severity}
                    </span>
                  </td>
                  <td className="px-5 py-4 text-muted-foreground tabular-nums font-mono">
                    {r.confidence != null ? `${r.confidence}%` : "—"}
                  </td>
                  {csvResults.length > 0 && (
                    <td className="px-5 py-4 text-xs">
                      <span className={`inline-flex items-center rounded-full px-2 py-0.5 font-medium ${
                        r.true_label === r.attack_type
                          ? "bg-emerald-500/15 text-emerald-400"
                          : r.true_label
                          ? "bg-yellow-500/15 text-yellow-400"
                          : "text-muted-foreground"
                      }`}>
                        {r.true_label || "—"}
                      </span>
                    </td>
                  )}
                  <td className="px-5 py-4 text-sm text-muted-foreground max-w-xs truncate">{r.solution}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </main>
  );
}