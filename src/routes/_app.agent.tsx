import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useRef, useState } from "react";
import { Bot, Send, Sparkles, User } from "lucide-react";
import { toast } from "sonner";

export const Route = createFileRoute("/_app/agent")({
  component: Agent,
  head: () => ({ meta: [{ title: "AI Agent — CyberShield" }] }),
});

type Msg = { role: "user" | "assistant"; content: string };

const SUGGESTIONS = [
  "What's the most critical threat right now?",
  "Summarize attacks from the last hour",
  "How do I mitigate the latest DDoS event?",
  "Which source IPs are most aggressive?",
];

function Agent() {
  const [messages, setMessages] = useState<Msg[]>([
    { role: "assistant", content: "Hi — I'm your SOC analyst agent. Ask me anything about your detections, or generate an incident report." },
  ]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [summary, setSummary] = useState("");
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => { scrollRef.current?.scrollTo({ top: 9e9, behavior: "smooth" }); }, [messages, busy]);

  // 1️⃣ قراءة الـ Logs مباشرة من الـ SQLite Local API بدلاً من Supabase
  const fetchLogs = async () => {
    try {
      const r = await fetch("http://127.0.0.1:8000/api/logs?limit=40");
      if (!r.ok) return [];
      const data = await r.json();
      return data ?? [];
    } catch (err) {
      console.error("Error fetching logs from local SQLite:", err);
      return [];
    }
  };

  // 2️⃣ تعديل الفانكشن لتستقبل الـ JSON الكامل من الـ Local API مباشرة
  const stream = async (mode: "chat" | "summary", payloadMsgs: Msg[], onDelta: (s: string) => void) => {
    try {
      const logs = await fetchLogs();
      const url = "http://127.0.0.1:8000/api/agent";
      
      const r = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ messages: payloadMsgs, mode, logs }),
      });

      if (r.status === 429) { toast.error("Rate limit reached"); return; }
      if (r.status === 402) { toast.error("AI credits exhausted"); return; }
      if (!r.ok) { toast.error("AI error"); return; }

      const data = await r.json();
      // استخراج محتوى الرسالة من الـ Response القادم من الـ FastAPI
      const content = data.choices?.[0]?.message?.content;
      if (content) {
        onDelta(content);
      }
    } catch (err) {
      console.error("Error communicating with Local AI Agent:", err);
      toast.error("Could not connect to the local API server");
    }
  };

  const send = async (text?: string) => {
    const content = (text ?? input).trim();
    if (!content || busy) return;
    setInput(""); setBusy(true);
    const userMsg: Msg = { role: "user", content };
    const newMsgs = [...messages, userMsg];
    setMessages([...newMsgs, { role: "assistant", content: "" }]);
    
    let acc = "";
    await stream("chat", newMsgs, (chunk) => {
      acc += chunk;
      setMessages((p) => p.map((m, i) => i === p.length - 1 ? { ...m, content: acc } : m));
    });
    setBusy(false);
  };

  const generateSummary = async () => {
    if (busy) return;
    setBusy(true); setSummary("");
    let acc = "";
    await stream("summary", [], (c) => { acc += c; setSummary(acc); });
    setBusy(false);
  };

  return (
    <main className="mx-auto grid max-w-7xl gap-4 px-6 py-8 lg:grid-cols-[1fr_380px]">
      <div className="glass-strong flex h-[calc(100vh-8rem)] flex-col rounded-2xl">
        <div className="flex items-center gap-3 border-b border-white/10 p-5">
          <div className="grid h-10 w-10 place-items-center rounded-xl" style={{ background: "var(--gradient-primary)" }}>
            <Bot className="h-5 w-5 text-primary-foreground" />
          </div>
          <div>
            <h1 className="text-lg font-semibold">SOC Analyst Agent</h1>
            <p className="text-xs text-muted-foreground">Live access to your detection telemetry</p>
          </div>
        </div>

        <div ref={scrollRef} className="flex-1 space-y-4 overflow-y-auto p-5">
          {messages.map((m, i) => (
            <div key={i} className={`flex gap-3 ${m.role === "user" ? "flex-row-reverse" : ""}`}>
              <div className={`grid h-8 w-8 shrink-0 place-items-center rounded-lg ${
                m.role === "user" ? "bg-primary/20 text-primary" : "bg-accent/20 text-accent"
              }`}>
                {m.role === "user" ? <User className="h-4 w-4" /> : <Bot className="h-4 w-4" />}
              </div>
              <div className={`max-w-[80%] whitespace-pre-wrap rounded-2xl px-4 py-2.5 text-sm ${
                m.role === "user" ? "bg-primary/15" : "glass"
              }`}>
                {m.content || <span className="text-muted-foreground">Thinking...</span>}
              </div>
            </div>
          ))}
        </div>

        {messages.length <= 1 && (
          <div className="flex flex-wrap gap-2 px-5">
            {SUGGESTIONS.map((s) => (
              <button key={s} onClick={() => send(s)}
                className="rounded-full glass px-3 py-1.5 text-xs hover:bg-white/10">{s}</button>
            ))}
          </div>
        )}

        <form onSubmit={(e) => { e.preventDefault(); send(); }} className="flex items-center gap-2 border-t border-white/10 p-4">
          <input value={input} onChange={(e) => setInput(e.target.value)} placeholder="Ask about a threat..."
            className="flex-1 rounded-xl border border-white/10 bg-white/5 px-4 py-2.5 text-sm outline-none focus:border-primary/60" />
          <button type="submit" disabled={busy}
            className="grid h-11 w-11 place-items-center rounded-xl text-primary-foreground transition-transform hover:scale-105 disabled:opacity-50"
            style={{ background: "var(--gradient-primary)" }}>
            <Send className="h-4 w-4" />
          </button>
        </form>
      </div>

      <aside className="glass-strong flex h-[calc(100vh-8rem)] flex-col rounded-2xl">
        <div className="flex items-center justify-between border-b border-white/10 p-5">
          <div className="flex items-center gap-2">
            <Sparkles className="h-4 w-4 text-accent" />
            <h2 className="text-sm font-semibold">Auto Incident Report</h2>
          </div>
          <button onClick={generateSummary} disabled={busy}
            className="rounded-lg px-3 py-1.5 text-xs font-medium text-primary-foreground disabled:opacity-50"
            style={{ background: "var(--gradient-primary)" }}>
            {busy ? "Generating..." : "Generate"}
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-5 text-sm">
          {summary ? (
            <div className="prose prose-invert prose-sm whitespace-pre-wrap text-foreground/90">{summary}</div>
          ) : (
            <p className="text-muted-foreground">Click Generate to produce an executive incident report from your latest detections.</p>
          )}
        </div>
      </aside>
    </main>
  );
}