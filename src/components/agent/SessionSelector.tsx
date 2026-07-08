// ═══════════════════════════════════════════════════════════════════════════════
// CYBERSHIELD AI — SESSION SELECTOR
// ═══════════════════════════════════════════════════════════════════════════════
// Allows users to switch between previous chat sessions.
// Each session is tied to a specific detection event.
// ═══════════════════════════════════════════════════════════════════════════════

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  History,
  ChevronDown,
  Trash2,
  Shield,
  AlertTriangle,
  Activity,
  Clock,
  X,
} from 'lucide-react';
import { useAgentStore } from '@/stores/agentStore';
import { getRiskLevel, RISK_CONFIG } from '@/types';

export function SessionSelector() {
  const { sessions, sessionId, loadSession, deleteSession, currentDetection } = useAgentStore();
  const [isOpen, setIsOpen] = useState(false);

  const currentSession = sessions.find((s) => s.sessionId === sessionId);

  if (sessions.length === 0) {
    return null;
  }

  return (
    <div className="relative">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-white/5 border border-white/10 hover:bg-white/10 text-sm text-foreground transition-all"
      >
        <History className="h-4 w-4 text-primary" />
        <span className="max-w-[150px] truncate">
          {currentSession?.attackType || 'Current Session'}
        </span>
        <ChevronDown
          className={`h-3.5 w-3.5 text-muted-foreground transition-transform ${
            isOpen ? 'rotate-180' : ''
          }`}
        />
      </button>

      <AnimatePresence>
        {isOpen && (
          <>
            {/* Backdrop */}
            <div className="fixed inset-0 z-40" onClick={() => setIsOpen(false)} />

            {/* Dropdown */}
            <motion.div
              initial={{ opacity: 0, y: -10, scale: 0.95 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: -10, scale: 0.95 }}
              transition={{ duration: 0.15 }}
              className="absolute right-0 top-full mt-2 w-80 rounded-xl bg-[#0f172a] border border-white/10 shadow-2xl shadow-black/50 z-50 overflow-hidden"
            >
              <div className="p-3 border-b border-white/10">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-foreground">Recent Sessions</h3>
                  <button
                    onClick={() => setIsOpen(false)}
                    className="p-1 rounded-md hover:bg-white/10 text-muted-foreground"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>

              <div className="max-h-80 overflow-y-auto">
                {sessions.map((session) => {
                  const riskLevel = getRiskLevel(session.confidence);
                  const riskConfig = RISK_CONFIG[riskLevel];
                  const isActive = session.sessionId === sessionId;

                  return (
                    <motion.button
                      key={session.sessionId}
                      whileHover={{ backgroundColor: 'rgba(255,255,255,0.05)' }}
                      onClick={() => {
                        loadSession(session.sessionId);
                        setIsOpen(false);
                      }}
                      className={`w-full flex items-start gap-3 p-3 text-left transition-colors ${
                        isActive ? 'bg-white/5 border-l-2 border-primary' : 'border-l-2 border-transparent'
                      }`}
                    >
                      {/* Severity Indicator */}
                      <div
                        className="shrink-0 w-2 h-2 mt-1.5 rounded-full"
                        style={{ backgroundColor: riskConfig.color.replace('text-', '').replace('-400', '') }}
                      />

                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between">
                          <span className="text-sm font-medium text-foreground truncate">
                            {session.attackType}
                          </span>
                          <span
                            className={`text-[10px] px-1.5 py-0.5 rounded ${riskConfig.bgColor} ${riskConfig.color}`}
                          >
                            {session.severity}
                          </span>
                        </div>

                        <div className="flex items-center gap-3 mt-1 text-[11px] text-muted-foreground">
                          <span className="flex items-center gap-1">
                            <Activity className="h-3 w-3" />
                            {session.confidence.toFixed(0)}%
                          </span>
                          <span className="flex items-center gap-1">
                            <Shield className="h-3 w-3" />
                            {session.protocol}
                          </span>
                          <span className="flex items-center gap-1">
                            <Clock className="h-3 w-3" />
                            {new Date(session.timestamp).toLocaleDateString()}
                          </span>
                        </div>

                        <p className="text-[11px] text-muted-foreground/70 mt-1 truncate">
                          {session.sourceIp}
                        </p>
                      </div>

                      {/* Delete Button */}
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          if (confirm('Delete this session?')) {
                            deleteSession(session.sessionId);
                          }
                        }}
                        className="shrink-0 p-1.5 rounded-md hover:bg-red-500/10 text-muted-foreground hover:text-red-400 transition-colors opacity-0 group-hover:opacity-100"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </motion.button>
                  );
                })}
              </div>

              {sessions.length > 5 && (
                <div className="p-2 text-center text-[11px] text-muted-foreground border-t border-white/10">
                  Showing {sessions.length} sessions
                </div>
              )}
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </div>
  );
}