// ═══════════════════════════════════════════════════════════════════════════════
// CYBERSHIELD AI — INITIAL ANALYSIS SECTION
// ═══════════════════════════════════════════════════════════════════════════════
// Displays attack analysis cards: type, severity, confidence, overview,
// root cause, immediate actions, prevention.
// ═══════════════════════════════════════════════════════════════════════════════

import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import {
  Shield,
  AlertTriangle,
  Activity,
  Globe,
  FileText,
  Zap,
  Lock,
  ChevronRight,
  Loader2,
} from 'lucide-react';
import { useAgentStore } from '@/stores/agentStore';
import { generateInitialAnalysis } from '@/services/agentService';
import type { AnalysisData, DetectionResult } from '@/types/agent';
import { getRiskLevel, RISK_CONFIG } from '@/types';

interface InitialAnalysisProps {
  detection: DetectionResult;
}

// Animation Variants 
const containerVariants = {
  hidden: { opacity: 0 },
  show: {
    opacity: 1,
    transition: { staggerChildren: 0.08 },
  },
};

const cardVariants = {
  hidden: { opacity: 0, y: 20 },
  show: { opacity: 1, y: 0, transition: { duration: 0.4 } },
};

// Severity Badge Component 
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

// ── Confidence Bar Component ─────────────────────────────────────────────────────
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

// ── Analysis Card Component ────────────────────────────────────────────────────
function AnalysisCard({
  title,
  icon,
  children,
  className = '',
  delay = 0,
}: {
  title: string;
  icon: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  delay?: number;
}) {
  return (
    <motion.div
      variants={cardVariants}
      className={`rounded-xl border border-white/10 bg-white/[0.03] backdrop-blur-sm p-4 hover:border-white/20 hover:bg-white/[0.05] transition-all duration-300 ${className}`}
    >
      <div className="flex items-center gap-2 mb-3">
        <div className="p-1.5 rounded-lg bg-primary/10 text-primary">{icon}</div>
        <h3 className="text-sm font-semibold text-foreground">{title}</h3>
      </div>
      {children}
    </motion.div>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────────
export function InitialAnalysis({ detection }: InitialAnalysisProps) {
  const { analysis, setAnalysis, isAnalysisLoading, setAnalysisLoading } = useAgentStore();
  const [error, setError] = useState<string | null>(null);

  const riskLevel = getRiskLevel(detection.confidence ?? 0);
  const riskConfig = RISK_CONFIG[riskLevel];

  useEffect(() => {
    // Only generate analysis if we don't have one for this attack type
    if (!analysis && !isAnalysisLoading) {
      generateAnalysis();
    }
  }, [detection.attack_type]);

  const generateAnalysis = async () => {
    setAnalysisLoading(true);
    setError(null);
    try {
      const response = await generateInitialAnalysis(detection);
      // Parse the AI response into structured analysis
      const parsed = parseAnalysisResponse(response.message);
      setAnalysis(parsed);
    } catch (err) {
      setError('Failed to generate analysis. Using fallback data.');
      setAnalysis(getFallbackAnalysis(detection));
    } finally {
      setAnalysisLoading(false);
    }
  };

  if (isAnalysisLoading) {
    return <AnalysisSkeleton />;
  }

  return (
    <motion.div
      variants={containerVariants}
      initial="hidden"
      animate="show"
      className="space-y-3"
    >
      {/* Header Row: Attack Type + Severity + Confidence */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {/* Attack Type Card */}
        <AnalysisCard title="Attack Type" icon={<Shield className="h-4 w-4" />}>
          <div className="flex items-center gap-3">
            <div className="text-2xl">
              {detection.attack_type.includes('DDoS') && '🌊'}
              {detection.attack_type.includes('Brute') && '🔑'}
              {detection.attack_type.includes('SQL') && '🌐'}
              {detection.attack_type.includes('XSS') && '🌐'}
              {detection.attack_type.includes('RCE') && '🌐'}
              {detection.attack_type.includes('Port') && '🔍'}
              {detection.attack_type.includes('Normal') && '✅'}
            </div>
            <div>
              <p className="text-lg font-bold text-foreground">{detection.attack_type}</p>
              <p className="text-xs text-muted-foreground">
                {detection.features?.protocol ?? 'Unknown'} • Port {detection.features?.dest_port??'N/A' }
              </p>
            </div>
          </div>
        </AnalysisCard>

        {/* Severity Card */}
        <AnalysisCard title="Severity" icon={<AlertTriangle className="h-4 w-4" />}>
          <div className="flex flex-col gap-2">
            <SeverityBadge severity={detection.severity} />
            <p className="text-xs text-muted-foreground mt-1">
              {riskConfig.description}
            </p>
          </div>
        </AnalysisCard>

        {/* Confidence Card */}
        <AnalysisCard title="Confidence" icon={<Activity className="h-4 w-4" />}>
          <ConfidenceBar confidence={detection.confidence} />
        </AnalysisCard>
      </div>

      {/* Source Info */}
      <AnalysisCard title="Source" icon={<Globe className="h-4 w-4" />} className="md:w-fit">
        <div className="flex items-center gap-4 text-sm">
          <div>
            <span className="text-muted-foreground">IP:</span>{' '}
            <span className="font-mono text-foreground">{detection.features?.source_ip??'N\A'}</span>
          </div>
          <div>
            <span className="text-muted-foreground">Protocol:</span>{' '}
            <span className="font-medium text-foreground">{detection.features?.protocol ?? 'Unknown'}</span>
          </div>
          {detection.features?.dest_port && (
            <div>
              <span className="text-muted-foreground">Port:</span>{' '}
              <span className="font-mono text-foreground">{detection.features?.dest_port??'N\A'}</span>
            </div>
          )}
        </div>
      </AnalysisCard>

      {/* Analysis Content */}
      {analysis && (
        <div className="grid grid-cols-1 gap-3">
          {/* Overview */}
          <AnalysisCard title="Overview" icon={<FileText className="h-4 w-4" />}>
            <p className="text-sm text-foreground/90 leading-relaxed">{analysis.overview}</p>
          </AnalysisCard>

          {/* Two Column: Root Cause + Immediate Actions */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <AnalysisCard title="Root Cause" icon={<Zap className="h-4 w-4" />}>
              <p className="text-sm text-foreground/90 leading-relaxed">{analysis.rootCause}</p>
            </AnalysisCard>

            <AnalysisCard title="Immediate Actions" icon={<AlertTriangle className="h-4 w-4" />}>
              <ul className="space-y-2">
                {analysis.immediateActions.map((action, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-foreground/90">
                    <ChevronRight className="h-4 w-4 text-primary shrink-0 mt-0.5" />
                    <span>{action}</span>
                  </li>
                ))}
              </ul>
            </AnalysisCard>
          </div>

          {/* Prevention */}
          <AnalysisCard title="Prevention" icon={<Lock className="h-4 w-4" />}>
            <ul className="space-y-2">
              {analysis.prevention.map((item, i) => (
                <li key={i} className="flex items-start gap-2 text-sm text-foreground/90">
                  <ChevronRight className="h-4 w-4 text-primary shrink-0 mt-0.5" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </AnalysisCard>

          {/* Tools & Best Practices (if available) */}
          {(analysis.tools.length > 0 || analysis.bestPractices.length > 0) && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {analysis.tools.length > 0 && (
                <AnalysisCard title="Recommended Tools" icon={<Shield className="h-4 w-4" />}>
                  <div className="flex flex-wrap gap-2">
                    {analysis.tools.map((tool, i) => (
                      <span
                        key={i}
                        className="px-2.5 py-1 rounded-md text-xs bg-primary/10 text-primary border border-primary/20"
                      >
                        {tool}
                      </span>
                    ))}
                  </div>
                </AnalysisCard>
              )}

              {analysis.bestPractices.length > 0 && (
                <AnalysisCard title="Best Practices" icon={<Lock className="h-4 w-4" />}>
                  <ul className="space-y-1.5">
                    {analysis.bestPractices.map((bp, i) => (
                      <li key={i} className="text-xs text-foreground/80 flex items-start gap-1.5">
                        <span className="text-primary mt-0.5">•</span>
                        {bp}
                      </li>
                    ))}
                  </ul>
                </AnalysisCard>
              )}
            </div>
          )}
        </div>
      )}

      {/* Error State */}
      {error && (
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/20">
          <p className="text-sm text-red-300">{error}</p>
          <button
            onClick={generateAnalysis}
            className="mt-2 text-xs text-red-400 hover:text-red-300 underline"
          >
            Retry Analysis
          </button>
        </div>
      )}
    </motion.div>
  );
}

// ── Skeleton Loading State ─────────────────────────────────────────────────────
function AnalysisSkeleton() {
  return (
    <div className="space-y-3 animate-pulse">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {[1, 2, 3].map((i) => (
          <div key={i} className="h-28 rounded-xl bg-white/5 border border-white/10" />
        ))}
      </div>
      <div className="h-32 rounded-xl bg-white/5 border border-white/10" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <div className="h-40 rounded-xl bg-white/5 border border-white/10" />
        <div className="h-40 rounded-xl bg-white/5 border border-white/10" />
      </div>
    </div>
  );
}

// ── Parse AI Response into Structured Analysis ─────────────────────────────────
function parseAnalysisResponse(message: string): AnalysisData {
  // Simple parser: extract sections from markdown-style response
  const sections = message.split(/#{2,3}\s+/);

  const findSection = (keywords: string[]): string => {
    const section = sections.find((s) =>
      keywords.some((k) => s.toLowerCase().includes(k.toLowerCase()))
    );
    return section ? section.replace(/^.+\n/, '').trim() : '';
  };

  const extractList = (text: string): string[] =>
    text
      .split('\n')
      .filter((line) => line.trim().match(/^[-\d*]\s+/))
      .map((line) => line.replace(/^[-\d*]\s+/, '').trim())
      .filter(Boolean);

  const overview = findSection(['Executive Summary', 'Overview', 'Summary']) || message.slice(0, 300);
  const rootCause = findSection(['Root Cause', 'Cause', 'Why']) || 'Analysis pending.';
  const actionsText = findSection(['Immediate Actions', 'Actions', 'Response']);
  const preventionText = findSection(['Prevention', 'Prevent', 'Mitigation']);

  return {
    overview,
    rootCause,
    immediateActions: extractList(actionsText).length > 0 ? extractList(actionsText) : ['Block source IP', 'Enable rate limiting', 'Review firewall rules'],
    prevention: extractList(preventionText).length > 0 ? extractList(preventionText) : ['Implement input validation', 'Use parameterized queries', 'Regular security audits'],
    tools: ['Wireshark', 'Snort', 'Suricata', 'Fail2Ban'],
    bestPractices: ['Keep systems updated', 'Monitor network traffic', 'Implement defense in depth'],
  };
}

// ── Fallback Analysis (when AI fails) ──────────────────────────────────────────
function getFallbackAnalysis(detection: DetectionResult): AnalysisData {
  const attackType = detection.attack_type;

  const fallbacks: Record<string, Partial<AnalysisData>> = {
    DDoS_UDP: {
      overview: 'A Distributed Denial of Service attack using UDP flood packets to overwhelm network resources.',
      rootCause: 'Attackers exploit UDP stateless nature to amplify traffic volume against target services.',
      immediateActions: ['Block source IP at firewall', 'Enable UDP rate limiting', 'Contact ISP for upstream filtering', 'Activate CDN DDoS protection'],
      prevention: ['Implement rate limiting', 'Use DDoS protection services', 'Monitor traffic patterns', 'Deploy anycast networking'],
    },
    SQL_Injection: {
      overview: 'An attack that injects malicious SQL code through user input fields to manipulate database queries.',
      rootCause: 'Insufficient input validation allows attacker-controlled data to be executed as SQL commands.',
      immediateActions: ['Block attacking IP', 'Review application logs', 'Patch vulnerable endpoints', 'Enable WAF rules'],
      prevention: ['Use parameterized queries', 'Implement input validation', 'Apply principle of least privilege', 'Regular code reviews'],
    },
  };

  const fallback = fallbacks[attackType] || {
    overview: `${attackType} attack detected with ${detection.confidence?.toFixed(1)}% confidence.`,
    rootCause: 'Attack vector analysis pending. Review network logs for detailed investigation.',
    immediateActions: ['Isolate affected systems', 'Review security logs', 'Apply latest patches', 'Monitor for lateral movement'],
    prevention: ['Implement defense in depth', 'Regular vulnerability scanning', 'Security awareness training', 'Incident response planning'],
  };

  return {
    overview: fallback.overview || '',
    rootCause: fallback.rootCause || '',
    immediateActions: fallback.immediateActions || [],
    prevention: fallback.prevention || [],
    tools: ['Wireshark', 'Nmap', 'Metasploit', 'Snort'],
    bestPractices: ['Regular updates', 'Network segmentation', 'Log monitoring', 'Backup strategy'],
  };
}