import { Send, Shield } from 'lucide-react';

export interface DetectionResult {
  attack_type: string;
  confidence: number | null;
  severity: string;
  detected_at?: string;
  time?: string;
  features: number[];
}

interface Props {
  detection: DetectionResult | null;
  onSend: () => void;
  isLoading: boolean;
}

export default function ChatInput({ detection, onSend, isLoading }: Props) {
  const handleSend = () => {
    if (isLoading || !detection) return;
    onSend();
  };

  const confidenceValue = detection?.confidence != null ? `${Math.round(detection.confidence)}%` : '—';
  const detectedAt = detection?.detected_at || detection?.time ? new Date(detection?.detected_at || detection?.time || '').toLocaleString() : '—';

  return (
    <div className="w-full bg-slate-900/95 backdrop-blur-xl border-t border-slate-700/50 p-4 shadow-2xl">
      <div className="max-w-5xl mx-auto space-y-4">
        <div className="bg-slate-800/80 border border-slate-700/70 rounded-[28px] p-5 shadow-xl shadow-slate-950/20 transition duration-200 hover:-translate-y-0.5">
          <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
            <div className="flex items-center gap-3">
              <div className="grid h-12 w-12 place-items-center rounded-3xl bg-gradient-to-br from-cyan-500/15 to-blue-600/15 text-cyan-300 shadow-sm shadow-cyan-500/10">
                <Shield className="w-6 h-6" />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-white">🚨 Current Detection</h2>
                <p className="text-sm text-slate-400">Real-time ML detection summary from the security pipeline.</p>
              </div>
            </div>

            <button
              type="button"
              onClick={handleSend}
              disabled={!detection || isLoading}
              className={`inline-flex items-center justify-center gap-2 rounded-2xl px-5 py-3 text-sm font-semibold transition duration-200 ${
                detection && !isLoading
                  ? 'bg-gradient-to-r from-cyan-500 to-blue-600 text-white shadow-lg shadow-cyan-500/20 hover:shadow-cyan-500/40 hover:scale-[1.02] active:scale-[0.98]'
                  : 'bg-slate-700/50 text-slate-500 cursor-not-allowed'
              }`}
            >
              <Send className="w-4 h-4" />
              Analyze with AI
            </button>
          </div>

          <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <div className="rounded-3xl border border-slate-700/60 bg-slate-950/70 p-4 shadow-sm shadow-slate-950/10">
              <div className="flex items-center justify-between gap-2 mb-2">
                <span className="text-xs uppercase tracking-[0.24em] text-slate-500">Attack Type</span>
                <span className="rounded-full bg-slate-700/70 px-2 py-1 text-[11px] uppercase text-slate-300">
                  Model Input
                </span>
              </div>
              <p className="text-sm text-white font-semibold">{detection?.attack_type ?? 'Waiting for attack detection...'}</p>
            </div>
            <div className="rounded-3xl border border-slate-700/60 bg-slate-950/70 p-4 shadow-sm shadow-slate-950/10">
              <div className="flex items-center justify-between gap-2 mb-2">
                <span className="text-xs uppercase tracking-[0.24em] text-slate-500">Confidence</span>
                <span className="rounded-full bg-blue-500/10 px-2 py-1 text-[11px] uppercase text-blue-300">ML Score</span>
              </div>
              <p className="text-sm text-white font-semibold">{detection ? confidenceValue : '—'}</p>
            </div>
            <div className="rounded-3xl border border-slate-700/60 bg-slate-950/70 p-4 shadow-sm shadow-slate-950/10">
              <div className="flex items-center justify-between gap-2 mb-2">
                <span className="text-xs uppercase tracking-[0.24em] text-slate-500">Risk Level</span>
                <span className="rounded-full bg-amber-500/10 px-2 py-1 text-[11px] uppercase text-amber-300">Severity</span>
              </div>
              <p className="text-sm text-white font-semibold">{detection?.severity ?? '—'}</p>
            </div>
            <div className="rounded-3xl border border-slate-700/60 bg-slate-950/70 p-4 shadow-sm shadow-slate-950/10">
              <div className="flex items-center justify-between gap-2 mb-2">
                <span className="text-xs uppercase tracking-[0.24em] text-slate-500">Detection Time</span>
                <span className="rounded-full bg-slate-700/70 px-2 py-1 text-[11px] uppercase text-slate-300">Timestamp</span>
              </div>
              <p className="text-sm text-white font-semibold">{detection ? detectedAt : 'Waiting for attack detection...'}</p>
            </div>
          </div>

          {!detection && (
            <div className="mt-5 rounded-3xl border border-dashed border-slate-700/60 bg-slate-950/70 p-4 text-center text-sm text-slate-400">
              Waiting for attack detection...
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
