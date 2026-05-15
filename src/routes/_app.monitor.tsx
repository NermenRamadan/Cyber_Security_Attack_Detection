import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import { Play, Square, Upload, X, FileText } from "lucide-react";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";
import { severityPillClass, type Attack } from "@/lib/mockAttacks";

export const Route = createFileRoute("/_app/monitor")({
  component: Monitor,
  head: () => ({ meta: [{ title: "Monitor — CyberShield" }] }),
});

const FEATURE_NAMES = [
  'deltatime', 'ip_flag_df', 'TCP Window Size', 'is_browser',
  'ip_flag_none', 'tcp_rst', 'is_attack_tool',
  'TCP Acknowledgment Number', 'is_http_1_0', 'has_dns_query',
  'TCP Sequence Number', 'TCP Destination Port', 'Length',
  'is_http_error', 'tcp_psh', 'TCP Stream', 'is_script',
  'is_http_response', 'TCP Source Port', 'HTTP Content-Length'
];

const API_URL = "http://127.0.0.1:8000";

function Monitor() {
  const navigate = useNavigate();
  const [running, setRunning] = useState(false);
  const [rows, setRows] = useState<Attack[]>([]);
  const channelRef = useRef<any>(null);

  // CSV upload state
  const [csvFile, setCsvFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [uploadTotal, setUploadTotal] = useState(0);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const abortRef = useRef(false);

  useEffect(() => {
    return () => {
      if (channelRef.current) supabase.removeChannel(channelRef.current);
    };
  }, []);

  const start = () => {
    if (running) return;
    setRunning(true);
    toast.success("Real-time monitoring started");

    channelRef.current = supabase
      .channel("monitor_live")
      .on(
        "postgres_changes",
        { event: "INSERT", schema: "public", table: "detection_logs" },
        (payload: any) => {
          const a: Attack = {
            id: payload.new.id,
            detected_at: payload.new.detected_at,
            source_ip: payload.new.source_ip,
            source_country: payload.new.source_country || "Unknown",
            status: payload.new.status || "detected",
            attack_type: payload.new.attack_type,
            protocol: payload.new.protocol || "TCP",
            severity: payload.new.severity,
            confidence: payload.new.confidence ?? 0,
            solution: payload.new.solution || "",
          };
          setRows((p) => [a, ...p].slice(0, 200));
        }
      )
      .subscribe();
  };

  const stop = () => {
    if (channelRef.current) supabase.removeChannel(channelRef.current);
    channelRef.current = null;
    setRunning(false);
    localStorage.removeItem("monitoring_start_time");
    toast.success("Monitoring stopped");
    setTimeout(() => navigate({ to: "/logs" }), 600);
  };

  // CSV Processing
  const parseCSV = (text: string): Record<string, string>[] => {
    const lines = text.trim().split("\n");
    if (lines.length < 2) return [];
    const headers = lines[0].split(",").map((h) => h.trim().replace(/"/g, ""));
    return lines.slice(1).map((line) => {
      const values = line.split(",").map((v) => v.trim().replace(/"/g, ""));
      const row: Record<string, string> = {};
      headers.forEach((h, i) => (row[h] = values[i] ?? "0"));
      return row;
    });
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (!file.name.endsWith(".csv")) {
      toast.error("Please upload a CSV file");
      return;
    }
    setCsvFile(file);
    toast.success(`File selected: ${file.name}`);
  };

  const handleUpload = async () => {
    if (!csvFile) return;

    setUploading(true);
    abortRef.current = false;
    setUploadProgress(0);

    try {
      const text = await csvFile.text();
      const rows = parseCSV(text);

      if (rows.length === 0) {
        toast.error("CSV is empty or invalid");
        setUploading(false);
        return;
      }

      // check if features exist
      const firstRow = rows[0];
      const missingFeatures = FEATURE_NAMES.filter((f) => !(f in firstRow));
      if (missingFeatures.length > 0) {
        toast.error(`Missing columns: ${missingFeatures.slice(0, 3).join(", ")}...`);
        setUploading(false);
        return;
      }

      setUploadTotal(rows.length);
      toast.success(`Processing ${rows.length} rows...`);

      let processed = 0;
      let attacks = 0;

      for (const row of rows) {
        if (abortRef.current) {
          toast.warning("Upload cancelled");
          break;
        }

        const features = FEATURE_NAMES.map((f) => parseFloat(row[f] ?? "0") || 0);
        const sourceIp = row["IP Source"] || row["source_ip"] || "0.0.0.0";

        try {
          const res = await fetch(`${API_URL}/predict`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              features,
              source_ip: sourceIp,
              protocol: "TCP",
              user_id: "",
            }),
          });

          if (res.ok) {
            const result = await res.json();
            if (result.is_attack) attacks++;
          }
        } catch {
          // skip failed rows silently
        }

        processed++;
        setUploadProgress(processed);

        // small delay عشان منضغطش على الـ API
        if (processed % 10 === 0) {
          await new Promise((r) => setTimeout(r, 50));
        }
      }

      if (!abortRef.current) {
        toast.success(`Done! Processed ${processed} rows — ${attacks} attacks found`);
      }
    } catch (e) {
      toast.error("Error reading file");
    } finally {
      setUploading(false);
      setUploadProgress(0);
      setUploadTotal(0);
    }
  };

  const cancelUpload = () => {
    abortRef.current = true;
  };

  const removeFile = () => {
    setCsvFile(null);
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  const progressPercent = uploadTotal > 0 ? Math.round((uploadProgress / uploadTotal) * 100) : 0;

  return (
    <main className="mx-auto max-w-7xl px-6 py-8">
      <div className="mb-6 flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
        <div>
          <h1 className="text-3xl font-semibold tracking-tight">Live Monitor</h1>
          <p className="text-sm text-muted-foreground">
            Real-time packet inspection & anomaly detection
          </p>
        </div>
        <div className="flex items-center gap-3">
          {!running ? (
            <button
              onClick={start}
              className="flex items-center gap-2 rounded-xl px-5 py-2.5 text-sm font-medium text-primary-foreground glow transition-transform hover:scale-105"
              style={{ background: "var(--gradient-primary)" }}
            >
              <Play className="h-4 w-4" /> Start Monitor
            </button>
          ) : (
            <button
              onClick={stop}
              className="flex items-center gap-2 rounded-xl bg-destructive/90 px-5 py-2.5 text-sm font-medium text-destructive-foreground transition-transform hover:scale-105"
            >
              <Square className="h-4 w-4" /> Stop Monitor
            </button>
          )}
        </div>
      </div>

      {/* CSV Upload Section */}
      <div className="mb-6 glass rounded-2xl p-5">
        <h2 className="text-base font-medium mb-1">Upload CSV Dataset</h2>
        <p className="text-xs text-muted-foreground mb-4">
          Test the model with your dataset — each row will be sent to the AI for prediction
        </p>

        <div className="flex flex-col gap-4 sm:flex-row sm:items-end">
          {/* File picker */}
          <div className="flex-1">
            {!csvFile ? (
              <label
                className="flex cursor-pointer flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed border-white/20 px-6 py-8 text-center transition-colors hover:border-primary/50 hover:bg-white/[0.02]"
                onClick={() => fileInputRef.current?.click()}
              >
                <Upload className="h-8 w-8 text-muted-foreground" />
                <span className="text-sm text-muted-foreground">
                  Click to select <span className="text-foreground font-medium">.csv</span> file
                </span>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".csv"
                  className="hidden"
                  onChange={handleFileChange}
                />
              </label>
            ) : (
              <div className="flex items-center gap-3 rounded-xl border border-white/10 bg-white/[0.03] px-4 py-3">
                <FileText className="h-5 w-5 text-primary shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium truncate">{csvFile.name}</p>
                  <p className="text-xs text-muted-foreground">
                    {(csvFile.size / 1024 / 1024).toFixed(2)} MB
                  </p>
                </div>
                {!uploading && (
                  <button onClick={removeFile} className="text-muted-foreground hover:text-foreground">
                    <X className="h-4 w-4" />
                  </button>
                )}
              </div>
            )}
          </div>

          {/* Upload button */}
          <div className="flex gap-2">
            {!uploading ? (
              <button
                onClick={handleUpload}
                disabled={!csvFile}
                className="flex items-center gap-2 rounded-xl px-5 py-2.5 text-sm font-medium text-primary-foreground transition-all hover:scale-105 disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:scale-100"
                style={{ background: csvFile ? "var(--gradient-primary)" : undefined, backgroundColor: !csvFile ? "rgba(255,255,255,0.1)" : undefined }}
              >
                <Upload className="h-4 w-4" /> Run Analysis
              </button>
            ) : (
              <button
                onClick={cancelUpload}
                className="flex items-center gap-2 rounded-xl bg-destructive/80 px-5 py-2.5 text-sm font-medium text-destructive-foreground transition-transform hover:scale-105"
              >
                <X className="h-4 w-4" /> Cancel
              </button>
            )}
          </div>
        </div>

        {/* Progress bar */}
        {uploading && (
          <div className="mt-4">
            <div className="mb-2 flex justify-between text-xs text-muted-foreground">
              <span>Processing rows...</span>
              <span>{uploadProgress} / {uploadTotal} ({progressPercent}%)</span>
            </div>
            <div className="h-2 overflow-hidden rounded-full bg-white/10">
              <div
                className="h-full rounded-full transition-all duration-300"
                style={{
                  width: `${progressPercent}%`,
                  background: "var(--gradient-primary)",
                }}
              />
            </div>
          </div>
        )}
      </div>

      {running && (
        <div className="mb-4 flex items-center gap-3 glass rounded-xl px-4 py-3 text-sm">
          <span className="relative flex h-3 w-3">
            <span className="absolute inset-0 rounded-full bg-success pulse-ring" />
            <span className="relative h-3 w-3 rounded-full bg-success" />
          </span>
          <span className="text-muted-foreground">
            Capturing packets in real time... Make sure Scapy is running.
          </span>
        </div>
      )}

      <div className="glass-strong overflow-hidden rounded-2xl">
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
              {rows.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-5 py-20 text-center text-muted-foreground">
                    Press <span className="text-foreground">Start Monitor</span> or upload a CSV to begin.
                  </td>
                </tr>
              )}
              {rows.map((r) => (
                <tr
                  key={r.id}
                  className="border-b border-white/5 last:border-0 transition-colors hover:bg-white/[0.04]"
                >
                  <td className="whitespace-nowrap px-5 py-4 text-muted-foreground tabular-nums">
                    {new Date(r.detected_at).toLocaleTimeString()}
                  </td>
                  <td className="px-5 py-4 font-mono text-sm text-foreground/90">{r.source_ip}</td>
                  <td className="px-5 py-4">
                    <span className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-medium ring-1 ${
                      r.status === "normal"
                        ? "bg-accent/15 text-accent ring-accent/30"
                        : "bg-destructive/15 text-destructive ring-destructive/30"
                    }`}>
                      {r.status}
                    </span>
                  </td>
                  <td className="px-5 py-4 font-medium">{r.attack_type}</td>
                  <td className="px-5 py-4 text-muted-foreground">{r.protocol}</td>
                  <td className="px-5 py-4">
                    <span className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ${severityPillClass(r.severity)}`}>
                      {r.severity}
                    </span>
                  </td>
                  <td className="px-5 py-4 text-muted-foreground tabular-nums">
                    {r.confidence ? `${(r.confidence * 100).toFixed(1)}%` : "—"}
                  </td>
                  <td className="px-5 py-4 text-sm text-muted-foreground max-w-md">{r.solution}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </main>
  );
}
