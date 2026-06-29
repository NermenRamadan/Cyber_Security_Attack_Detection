import { createFileRoute, Link } from "@tanstack/react-router";
import { Shield, Activity, Bot, Zap, Globe, Lock } from "lucide-react";

export const Route = createFileRoute("/")({
  component: Home,
  head: () => ({
    meta: [
      { title: "CyberShield — Real-Time Cyber Attack Detection" },
      { name: "description", content: "AI-powered real-time cyber attack detection and response." },
    ],
  }),
});

const FEATURES = [
  { icon: Activity, title: "Real-Time Monitoring", desc: "Stream packets and detect anomalies as they happen." },
  { icon: Shield, title: "Multi-Vector Defense", desc: "DDoS, SQLi, XSS, brute force and zero-day coverage." },
  { icon: Bot, title: "AI Incident Agent", desc: "Conversational analyst with auto-generated playbooks." },
  { icon: Globe, title: "Geo Threat Map", desc: "Visualize attack origins across the globe live." },
  { icon: Zap, title: "Sub-Second Response", desc: "Automated mitigation triggered in milliseconds." },
  { icon: Lock, title: "Zero Trust Logs", desc: "RLS-secured per-user log storage with full history." },
];

function Home() {
  return (
    <main className="relative">
      <section className="mx-auto flex max-w-7xl flex-col items-center px-6 pt-24 pb-20 text-center">
        <div className="mb-6 flex items-center gap-2 rounded-full glass px-4 py-1.5 text-xs uppercase tracking-widest text-muted-foreground">
          <span className="h-2 w-2 animate-pulse rounded-full bg-success" />
          Live threat intelligence
        </div>
        <h1 className="max-w-4xl text-5xl font-semibold leading-[1.05] tracking-tight md:text-7xl">
          Real-time <span className="text-gradient">cyber attack</span> detection,
          powered by AI.
        </h1>
        <p className="mt-6 max-w-2xl text-lg text-muted-foreground">
          CyberShield watches every packet, scores every anomaly, and stops threats before they breach.
          Built for analysts who refuse to blink.
        </p>
        <div className="mt-10 flex flex-wrap items-center justify-center gap-3">
          <Link
            to="/register"
            className="rounded-xl px-6 py-3 text-sm font-medium text-primary-foreground glow transition-transform hover:scale-105"
            style={{ background: "var(--gradient-primary)" }}
          >
            Launch the dashboard
          </Link>
          <Link to="/login" className="rounded-xl glass px-6 py-3 text-sm font-medium hover:bg-white/10">
            Sign in
          </Link>
        </div>

        <div className="mt-16 grid w-full grid-cols-3 gap-4 md:max-w-3xl">
          {[
            { v: "24M+", l: "Packets / sec" },
            { v: "99.98%", l: "Detection rate" },
            { v: "<120ms", l: "Response time" },
          ].map((s) => (
            <div key={s.l} className="glass rounded-2xl p-5">
              <div className="text-2xl font-semibold text-gradient md:text-3xl">{s.v}</div>
              <div className="mt-1 text-xs uppercase tracking-wider text-muted-foreground">{s.l}</div>
            </div>
          ))}
        </div>
      </section>

      <section className="mx-auto max-w-7xl px-6 pb-24">
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {FEATURES.map((f) => {
            const Icon = f.icon;
            return (
              <div key={f.title} className="glass group rounded-2xl p-6 transition-all hover:bg-white/[0.07]">
                <div className="mb-4 grid h-11 w-11 place-items-center rounded-xl bg-primary/10 text-primary transition-transform group-hover:scale-110">
                  <Icon className="h-5 w-5" />
                </div>
                <h3 className="text-lg font-medium">{f.title}</h3>
                <p className="mt-1.5 text-sm text-muted-foreground">{f.desc}</p>
              </div>
            );
          })}
        </div>
      </section>
    </main>
  );
}
