// @ts-nocheck
import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: cors });
  try {
    const { messages, mode = "chat", logs = [] } = await req.json();
    const KEY = Deno.env.get("LOVABLE_API_KEY");
    if (!KEY) throw new Error("LOVABLE_API_KEY missing");

    const ctx = logs.length
      ? `Recent detections (most recent first):\n${logs.slice(0, 25).map((l: any) =>
          `- [${l.severity}] ${l.attack_type} via ${l.protocol} from ${l.source_ip} @ ${new Date(l.detected_at).toLocaleString()} (conf ${l.confidence}%)`
        ).join("\n")}`
      : "No recent detections available.";

    const systemChat = `You are SentinelAI, a senior SOC analyst. Be concise, technical, and actionable.
You have access to recent detection telemetry below. Reference specific events when relevant.
${ctx}`;

    const systemSummary = `You are SentinelAI. Generate a crisp incident report from the telemetry below.
Output sections: ## Executive Summary, ## Top Threats, ## Recommended Actions (numbered, prioritized), ## Response Playbook.
Telemetry:
${ctx}`;

    const body = mode === "summary"
      ? { model: "google/gemini-3-flash-preview", messages: [
          { role: "system", content: systemSummary },
          { role: "user", content: "Generate the incident report now." },
        ], stream: true }
      : { model: "google/gemini-3-flash-preview", messages: [
          { role: "system", content: systemChat }, ...messages,
        ], stream: true };

    const r = await fetch("https://ai.gateway.lovable.dev/v1/chat/completions", {
      method: "POST",
      headers: { Authorization: `Bearer ${KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    if (r.status === 429) return new Response(JSON.stringify({ error: "Rate limit reached. Try again in a moment." }), { status: 429, headers: { ...cors, "Content-Type": "application/json" } });
    if (r.status === 402) return new Response(JSON.stringify({ error: "AI credits exhausted. Add funds in workspace settings." }), { status: 402, headers: { ...cors, "Content-Type": "application/json" } });
    if (!r.ok) return new Response(JSON.stringify({ error: "AI gateway error" }), { status: 500, headers: { ...cors, "Content-Type": "application/json" } });

    return new Response(r.body, { headers: { ...cors, "Content-Type": "text/event-stream" } });
  } catch (e) {
    return new Response(JSON.stringify({ error: (e as Error).message }), { status: 500, headers: { ...cors, "Content-Type": "application/json" } });
  }
});
