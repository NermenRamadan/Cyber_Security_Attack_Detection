import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { useState } from "react";
import { toast } from "sonner";
import { Shield } from "lucide-react";

// عنوان الـ Backend (API.py) — عدّليه لو شغال على بورت أو دومين مختلف
const API_URL = "http://localhost:8000";

export const Route = createFileRoute("/register")({
  component: RegisterPage,
  head: () => ({ meta: [{ title: "Create account — CyberShield" }] }),
});

function RegisterPage() {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      });
      const data = await res.json();

      if (!res.ok) {
        toast.error(data.detail || "Could not create account");
        setLoading(false);
        return;
      }

      // بنحفظ الـ user_id عشان كل الـ requests بعد كدا تبقى مرتبطة بيه
      localStorage.setItem("user_id", data.user_id);
      localStorage.setItem("user_email", data.email);

      toast.success("Account created!");
      navigate({ to: "/dashboard" });
    } catch (err) {
      toast.error("Could not reach the server. Is the API running?");
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="flex min-h-[calc(100vh-4rem)] items-center justify-center px-6 py-12">
      <form onSubmit={submit} className="glass-strong w-full max-w-md rounded-2xl p-8">
        <div className="mb-6 flex items-center gap-3">
          <div className="grid h-10 w-10 place-items-center rounded-lg" style={{ background: "var(--gradient-primary)" }}>
            <Shield className="h-5 w-5 text-primary-foreground" />
          </div>
          <div>
            <h1 className="text-xl font-semibold">Create your sentinel</h1>
            <p className="text-sm text-muted-foreground">Start defending in minutes</p>
          </div>
        </div>

        <label className="mb-4 block">
          <span className="mb-1.5 block text-sm text-muted-foreground">Email</span>
          <input
            type="email" required value={email} onChange={(e) => setEmail(e.target.value)}
            className="w-full rounded-lg border border-white/10 bg-white/5 px-4 py-2.5 text-sm outline-none focus:border-primary/60 focus:ring-2 focus:ring-primary/30"
            placeholder="you@company.com"
          />
        </label>
        <label className="mb-6 block">
          <span className="mb-1.5 block text-sm text-muted-foreground">Password</span>
          <input
            type="password" required minLength={6} value={password} onChange={(e) => setPassword(e.target.value)}
            className="w-full rounded-lg border border-white/10 bg-white/5 px-4 py-2.5 text-sm outline-none focus:border-primary/60 focus:ring-2 focus:ring-primary/30"
            placeholder="••••••••"
          />
        </label>
        <button
          disabled={loading}
          className="w-full rounded-lg py-2.5 text-sm font-medium text-primary-foreground transition-transform hover:scale-[1.02] disabled:opacity-60"
          style={{ background: "var(--gradient-primary)" }}
        >
          {loading ? "Creating..." : "Create account"}
        </button>
        <p className="mt-6 text-center text-sm text-muted-foreground">
          Already have one? <Link to="/login" className="text-primary hover:underline">Sign in</Link>
        </p>
      </form>
    </main>
  );
}
