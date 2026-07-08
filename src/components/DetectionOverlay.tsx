// ═══════════════════════════════════════════════════════════════════════════════
// CYBERSHIELD AI — DETECTION OVERLAY
// ═══════════════════════════════════════════════════════════════════════════════
// Displays detection results and navigates to Agent page with attack data.
// Bridges the gap between Detection and Agent via Zustand store.
// ═══════════════════════════════════════════════════════════════════════════════

import { useNavigate } from '@tanstack/react-router';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield,
  AlertTriangle,
  Activity,
  Globe,
  ArrowRight,
  X,
  Zap,
  Lock,
  FileText,
  Bot,
  Clock,
  ChevronRight,
} from 'lucide-react';
import { useAgentStore } from '@/stores/agentStore';
import type { DetectionResult } from '@/types/agent';
import { getRiskLevel, RISK_CONFIG } from '@/types';
import { useState } from 'react';

interface DetectionOverlayProps {
  isOpen: boolean;
  onClose: () => void;
  detection: DetectionResult | null;
}

// ── Severity Badge ─────────────────────────────────────────────────────────────
function SeverityBadge({ severity }: { severity: string }) {
  const config = RISK_CONFIG[severity as keyof typeof RISK_CONFIG] || RISK_CONFIG.Low;
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider ${config.bgColor} ${config.color} border ${config.borderColor}`}
    >
      {config.icon} {severity}
    </span>
  );
}

// ── Confidence Bar ────────────────────────────────────────────────────────────
function ConfidenceBar({ confidence }: { confidence: number | null }) {
  const value = confidence ?? 0;
  const riskLevel = getRiskLevel(value);
  const config = RISK_CONFIG[riskLevel];

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-xs text-muted-foreground">Confidence</span>
        <span className={`text-sm font-bold ${config.color}`}>{value.toFixed(1)}%</span>
      </div>
      <div className="h-2 rounded-full bg-white/10 overflow-hidden">
        <motion.div
          className="h-full rounded-full"
          style={{ backgroundColor: config.color.replace('text-', '').replace('-400', '') }}
          initial={{ width: 0 }}
          animate={{ width: `${value}%` }}
          transition={{ duration: 1, ease: 'easeOut' }}
        />
      </div>
    </div>
  );
}

// ── Quick Info Card ────────────────────────────────────────────────────────────
function QuickInfoCard({
  icon,
  label,
  value,
  delay = 0,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  delay?: number;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.3 }}
      className="flex items-center gap-3 p-3 rounded-xl bg-white/5 border border-white/10"
    >
      <div className="p-2 rounded-lg bg-primary/10 text-primary">{icon}</div>
      <div>
        <p className="text-[10px] text-muted-foreground uppercase tracking-wider">{label}</p>
        <p className="text-sm font-medium text-foreground">{value}</p>
      </div>
    </motion.div>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────────
export function DetectionOverlay({ isOpen, onClose, detection }: DetectionOverlayProps) {
  const navigate = useNavigate();
  const { setCurrentDetection } = useAgentStore();

  if (!detection) return null;

  const riskLevel = getRiskLevel(detection.confidence ?? 0);
  const riskConfig = RISK_CONFIG[riskLevel];

  const handleGoToAgent = () => {
    // Store detection in Zustand store
    setCurrentDetection(detection);
    // Close overlay
    onClose();
    // Navigate to agent page
    navigate({ to: '/agent' });
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50"
            onClick={onClose}
          />

          {/* Overlay Panel */}
          <motion.div
            initial={{ opacity: 0, scale: 0.95, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 20 }}
            transition={{ duration: 0.3, ease: 'easeOut' }}
            className="fixed inset-4 md:inset-auto md:top-1/2 md:left-1/2 md:-translate-x-1/2 md:-translate-y-1/2 md:w-full md:max-w-2xl md:max-h-[85vh] z-50 overflow-hidden"
          >
            <div className="h-full rounded-2xl bg-[#0f172a] border border-white/10 shadow-2xl shadow-black/50 overflow-hidden flex flex-col">
              {/* Header */}
              <div className="flex items-center justify-between p-5 border-b border-white/10">
                <div className="flex items-center gap-3">
                  <div
                    className="w-10 h-10 rounded-xl flex items-center justify-center"
                    style={{ backgroundColor: `${riskConfig.color.replace('text-', '').replace('-400', '')}20` }}
                  >
                    <Shield
                      className="h-5 w-5"
                      style={{ color: riskConfig.color.replace('text-', '').replace('-400', '') }}
                    />
                  </div>
                  <div>
                    <h2 className="text-lg font-semibold text-foreground">Attack Detected</h2>
                    <p className="text-xs text-muted-foreground">
                      {new Date().toLocaleString()}
                    </p>
                  </div>
                </div>
                <button
                  onClick={onClose}
                  className="p-2 rounded-lg hover:bg-white/10 text-muted-foreground hover:text-foreground transition-colors"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>

              {/* Content */}
              <div className="flex-1 overflow-y-auto p-5 space-y-4">
                {/* Attack Type & Severity */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className="text-3xl">
                      {detection.attack_type.includes('DDoS') && '🌊'}
                      {detection.attack_type.includes('Brute') && '🔑'}
                      {detection.attack_type.includes('SQL') && '🌐'}
                      {detection.attack_type.includes('XSS') && '🌐'}
                      {detection.attack_type.includes('RCE') && '🌐'}
                      {detection.attack_type.includes('Port') && '🔍'}
                      {detection.attack_type.includes('Normal') && '✅'}
                      {detection.attack_type.includes('Fuzzing') && '🔨'}
                    </span>
                    <div>
                      <h3 className="text-xl font-bold text-foreground">{detection.attack_type}</h3>
                      <p className="text-xs text-muted-foreground">
                        {detection.features.protocol} • Port {detection.features.dest_port || 'N/A'}
                      </p>
                    </div>
                  </div>
                  <SeverityBadge severity={detection.severity} />
                </div>

                {/* Confidence Bar */}
                <ConfidenceBar confidence={detection.confidence} />

                {/* Quick Info Grid */}
                <div className="grid grid-cols-2 gap-3">
                  <QuickInfoCard
                    icon={<Globe className="h-4 w-4" />}
                    label="Source IP"
                    value={detection.features.source_ip}
                    delay={0.1}
                  />
                  <QuickInfoCard
                    icon={<Activity className="h-4 w-4" />}
                    label="Protocol"
                    value={detection.features.protocol}
                    delay={0.15}
                  />
                  {detection.features.dest_port && (
                    <QuickInfoCard
                      icon={<Zap className="h-4 w-4" />}
                      label="Destination Port"
                      value={String(detection.features.dest_port)}
                      delay={0.2}
                    />
                  )}
                  {detection.features.length && (
                    <QuickInfoCard
                      icon={<FileText className="h-4 w-4" />}
                      label="Packet Length"
                      value={`${detection.features.length} bytes`}
                      delay={0.25}
                    />
                  )}
                </div>

                {/* Solution */}
                {detection.solution && (
                  <motion.div
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.3 }}
                    className="p-4 rounded-xl bg-primary/5 border border-primary/20"
                  >
                    <div className="flex items-center gap-2 mb-2">
                      <Lock className="h-4 w-4 text-primary" />
                      <h4 className="text-sm font-semibold text-primary">Recommended Action</h4>
                    </div>
                    <p className="text-sm text-foreground/90">{detection.solution}</p>
                  </motion.div>
                )}

                {/* Binary Confidence */}
                {detection.binary_confidence && (
                  <motion.div
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.35 }}
                    className="flex items-center justify-between p-3 rounded-xl bg-white/5 border border-white/10"
                  >
                    <span className="text-xs text-muted-foreground">Detection Confidence</span>
                    <span className="text-sm font-medium text-foreground">
                      {detection.binary_confidence.toFixed(1)}%
                    </span>
                  </motion.div>
                )}
              </div>

              {/* Footer Actions */}
              <div className="p-5 border-t border-white/10 space-y-3">
                {/* Primary Action: Go to Agent */}
                <motion.button
                  whileHover={{ scale: 1.02 }}
                  whileTap={{ scale: 0.98 }}
                  onClick={handleGoToAgent}
                  className="w-full flex items-center justify-center gap-2 px-4 py-3 rounded-xl bg-primary text-primary-foreground font-medium hover:bg-primary/90 transition-colors"
                >
                  <Bot className="h-5 w-5" />
                  Analyze with AI Agent
                  <ArrowRight className="h-4 w-4" />
                </motion.button>

                {/* Secondary Actions */}
                <div className="flex gap-3">
                  <button
                    onClick={onClose}
                    className="flex-1 px-4 py-2.5 rounded-xl bg-white/5 border border-white/10 hover:bg-white/10 text-sm text-foreground transition-colors"
                  >
                    Dismiss
                  </button>
                  <button
                    onClick={() => {
                      // Save to logs or export
                      navigator.clipboard.writeText(JSON.stringify(detection, null, 2));
                      // You can add toast here
                    }}
                    className="flex-1 px-4 py-2.5 rounded-xl bg-white/5 border border-white/10 hover:bg-white/10 text-sm text-foreground transition-colors"
                  >
                    Copy Details
                  </button>
                </div>
              </div>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}

// ── Hook: Use Detection Overlay ────────────────────────────────────────────────
export function useDetectionOverlay() {
  const [isOpen, setIsOpen] = useState(false);
  const [detection, setDetection] = useState<DetectionResult | null>(null);

  const open = (data: DetectionResult) => {
    setDetection(data);
    setIsOpen(true);
  };

  const close = () => {
    setIsOpen(false);
    // Optional: clear after animation
    setTimeout(() => setDetection(null), 300);
  };

  return { isOpen, open, close, detection };
}