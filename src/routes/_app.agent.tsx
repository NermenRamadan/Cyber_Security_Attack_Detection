// ═══════════════════════════════════════════════════════════════════════════════
// CYBERSHIELD AI — AGENT PAGE (Complete Rewrite)
// ═══════════════════════════════════════════════════════════════════════════════
// Layout: Single column with 4 sections:
//   1. Initial Analysis (cards)
//   2. Quick Suggestions (dynamic chips)
//   3. Free Chat (with memory)
//   4. Related References (RAG-ready)
// ═══════════════════════════════════════════════════════════════════════════════

import { createFileRoute } from '@tanstack/react-router';
import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import {
  Bot,
  Shield,
  AlertTriangle,
  ArrowLeft,
  Loader2,
} from 'lucide-react';
import { toast } from 'sonner';

import { useAgentStore } from '@/stores/agentStore';
import { fetchLatestDetection } from '@/services/agentService';
import { InitialAnalysis } from '@/components/agent/InitialAnalysis';
import { AttackSuggestions } from '@/components/agent/AttackSuggestions';
import { ChatSection } from '@/components/agent/ChatSection';
import { RelatedReferences } from '@/components/agent/RelatedReferences';
import { SessionSelector } from '@/components/agent/SessionSelector';
import type { DetectionResult } from '@/types/agent';

export const Route = createFileRoute('/_app/agent')({
  component: Agent,
  head: () => ({ meta: [{ title: 'AI Agent — CyberShield' }] }),
});

// ── No Detection Fallback ────────────────────────────────────────────────────
function NoDetectionState({ onRefresh }: { onRefresh: () => void }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="flex flex-col items-center justify-center min-h-[60vh] text-center px-6"
    >
      <div className="w-20 h-20 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center mb-6">
        <Shield className="h-10 w-10 text-muted-foreground" />
      </div>
      <h2 className="text-xl font-semibold text-foreground mb-2">No Active Detection</h2>
      <p className="text-sm text-muted-foreground max-w-md mb-6">
        There is no active attack detection to analyze. Start a detection scan from the dashboard,
        or load a previous session from the history.
      </p>
      <div className="flex gap-3">
        <button
          onClick={() => window.history.back()}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-white/5 border border-white/10 hover:bg-white/10 text-sm text-foreground transition-all"
        >
          <ArrowLeft className="h-4 w-4" />
          Go Back
        </button>
        <button
          onClick={onRefresh}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-xl bg-primary text-primary-foreground hover:bg-primary/90 text-sm transition-all"
        >
          <Loader2 className="h-4 w-4" />
          Check for Detections
        </button>
      </div>
    </motion.div>
  );
}

// ── Main Agent Component ───────────────────────────────────────────────────────
function Agent() {
  const {
    currentDetection,
    setCurrentDetection,
    messages,
    addMessage,
    sessionId,
  } = useAgentStore();

  const [isLoading, setIsLoading] = useState(!currentDetection);
  const [error, setError] = useState<string | null>(null);

  // Load detection on mount
  useEffect(() => {
    if (!currentDetection) {
      loadDetection();
    }
  }, []);

  const loadDetection = async () => {
    setIsLoading(true);
    setError(null);
    try {
      // Try to get from store first (set by DetectionOverlay)
      if (currentDetection) {
        setIsLoading(false);
        return;
      }

      // Fallback: fetch latest from backend
      const detection = await fetchLatestDetection();
      if (detection) {
        setCurrentDetection(detection);
      }
    } catch (err) {
      setError('Failed to load detection data');
      toast.error('Could not load detection data');
    } finally {
      setIsLoading(false);
    }
  };

  // Handle suggestion click
  const handleSuggestionClick = (prompt: string) => {
    // Add user message
    const userMsg = {
      id: crypto.randomUUID(),
      role: 'user' as const,
      content: prompt,
      timestamp: new Date().toISOString(),
    };
    addMessage(userMsg);

    // Trigger AI response (ChatSection will handle the API call)
    // We need to pass this to ChatSection somehow
    // For now, we'll add a custom event or use the store
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  if (!currentDetection) {
    return <NoDetectionState onRefresh={loadDetection} />;
  }

  return (
    <main className="mx-auto max-w-4xl px-4 py-6 md:px-6">
      {/* Header */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex items-center justify-between mb-6"
      >
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-primary/20 flex items-center justify-center">
            <Bot className="h-5 w-5 text-primary" />
          </div>
          <div>
            <h1 className="text-lg font-semibold text-foreground">SOC Analyst Agent</h1>
            <p className="text-xs text-muted-foreground">
              Analyzing: {currentDetection.attack_type} • {currentDetection.severity}
            </p>
          </div>
        </div>
        <SessionSelector />
      </motion.div>

      {/* Section 1: Initial Analysis */}
      <section className="mb-6">
        <InitialAnalysis detection={currentDetection} />
      </section>

      {/* Section 2: Quick Suggestions */}
      <section className="mb-6 p-4 rounded-xl bg-white/[0.02] border border-white/10">
        <AttackSuggestions
          attackType={currentDetection.attack_type}
          onSuggestionClick={handleSuggestionClick}
        />
      </section>

      {/* Section 3: Free Chat */}
      <section className="mb-6">
        <ChatSection />
      </section>

      {/* Section 4: Related References */}
      <section className="mb-8">
        <RelatedReferences attackType={currentDetection.attack_type} />
      </section>

      {/* Footer */}
      <footer className="text-center text-xs text-muted-foreground/50 pb-6">
        <p>
          CyberShield AI Agent • Session: {sessionId?.slice(0, 8) || 'N/A'} •
          Powered by SentinelAI
        </p>
      </footer>
    </main>
  );
}