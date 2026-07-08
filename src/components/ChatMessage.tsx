import { memo, useEffect, useMemo, useState, type ReactNode } from 'react';
import {
  Shield,
  User,
  Clock,
  AlertTriangle,
  CheckCircle,
  Zap,
  Lock,
  BookOpen,
  ShieldCheck,
  BarChart3,
} from 'lucide-react';
import type { ChatMessage as ChatMessageType } from '@/types';
import { RISK_CONFIG } from '@/types';

interface Props {
  message: ChatMessageType;
}

const loadingMessages = [
  'Analyzing network traffic...',
  'Correlating indicators...',
  'Generating incident response...',
];

const sectionCardClass =
  'bg-slate-800/80 backdrop-blur-sm rounded-2xl rounded-tl-sm p-5 border border-slate-700/50 shadow-lg transition duration-200 hover:-translate-y-0.5 hover:border-slate-500/70';

function SectionCard({
  icon,
  title,
  accentClass,
  children,
}: {
  icon: JSX.Element;
  title: string;
  accentClass: string;
  children: ReactNode;
}) {
  return (
    <div className={sectionCardClass}>
      <div className="flex items-center gap-2 mb-3">
        {icon}
        <h3 className={`text-sm font-semibold uppercase tracking-wider ${accentClass}`}>
          {title}
        </h3>
      </div>
      <div className="text-slate-300 text-sm leading-relaxed">{children}</div>
    </div>
  );
}

function MetricCard({
  title,
  value,
  icon,
  accentClass,
}: {
  title: string;
  value: string | number;
  icon: JSX.Element;
  accentClass: string;
}) {
  return (
    <div className="rounded-3xl border border-slate-700/60 bg-slate-900/80 p-4 shadow-sm shadow-slate-900/10 transition duration-200 hover:-translate-y-0.5">
      <div className="flex items-center justify-between gap-3 mb-4">
        <div className={`inline-flex items-center justify-center rounded-2xl p-2 ${accentClass}`}>
          {icon}
        </div>
        <span className="text-xs uppercase tracking-[0.22em] text-slate-500">{title}</span>
      </div>
      <p className="text-white font-semibold text-lg leading-snug">{value}</p>
    </div>
  );
}

function ToolBadge({ tool }: { tool: string }) {
  return (
    <span className="inline-flex items-center gap-1 rounded-full border border-slate-600/60 bg-slate-700/70 px-3 py-1.5 text-xs text-slate-200 transition duration-200 hover:bg-slate-600/80 hover:shadow-sm hover:shadow-cyan-500/10">
      {tool}
    </span>
  );
}

export function ChatMessage({ message }: Props) {
  const [loadingIndex, setLoadingIndex] = useState(0);
  const isUser = message.role === 'user';
  const responseData = message.responseData;
  const riskLevel = message.riskLevel;
  const riskConfig = riskLevel ? RISK_CONFIG[riskLevel] : null;

  useEffect(() => {
    if (!message.isLoading) {
      return;
    }

    setLoadingIndex(0);
    const interval = window.setInterval(() => {
      setLoadingIndex((value) => (value + 1) % loadingMessages.length);
    }, 1400);

    return () => window.clearInterval(interval);
  }, [message.isLoading]);

  const loadingText = loadingMessages[loadingIndex];

  const confidence = useMemo(() => Math.max(0, Math.min(100, message.confidence ?? 0)), [message.confidence]);
  const attackType = useMemo(() => message.attackType ?? 'Unknown', [message.attackType]);
  const progressFillClass = useMemo(
    () => riskConfig?.color.replace('text-', 'bg-') ?? 'bg-cyan-500',
    [riskConfig]
  );

  const referenceItems = useMemo(() => {
    if (!responseData) return [] as Array<{ label: string; values: string[] }>;

    return [
      { label: 'MITRE ATT&CK', values: (responseData as any).mitre_attack },
      { label: 'OWASP Reference', values: (responseData as any).owasp_reference },
      { label: 'NIST Reference', values: (responseData as any).nist_reference },
    ]
      .filter((item) => Array.isArray(item.values) && item.values.length > 0)
      .map((item) => ({ label: item.label, values: item.values as string[] }));
  }, [responseData]);

  if (message.isLoading) {
    return (
      <div className="flex items-start gap-3 animate-pulse">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
          <Shield className="w-5 h-5 text-white" />
        </div>
        <div className="flex-1 max-w-3xl">
          <div className="bg-slate-800/80 backdrop-blur-sm rounded-2xl rounded-tl-sm p-4 border border-slate-700/50">
            <div className="flex items-center gap-2 text-cyan-400">
              <div className="w-2 h-2 rounded-full bg-cyan-400 animate-bounce" />
              <div className="w-2 h-2 rounded-full bg-cyan-400 animate-bounce delay-100" />
              <div className="w-2 h-2 rounded-full bg-cyan-400 animate-bounce delay-200" />
              <span className="text-sm ml-2">{loadingText}</span>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (isUser) {
    return (
      <div className="flex items-start gap-3 justify-end animate-in slide-in-from-right-4 duration-300">
        <div className="flex-1 max-w-3xl">
          <div className="bg-gradient-to-r from-cyan-600 to-blue-600 rounded-2xl rounded-tr-sm p-4 shadow-lg shadow-cyan-500/10">
            <p className="text-white text-sm leading-relaxed">{message.content}</p>
            <div className="flex items-center gap-1 mt-2 justify-end">
              <Clock className="w-3 h-3 text-white/60" />
              <span className="text-xs text-white/60">
                {message.timestamp.toLocaleTimeString()}
              </span>
            </div>
          </div>
        </div>
        <div className="w-10 h-10 rounded-xl bg-slate-700 flex items-center justify-center shadow-lg">
          <User className="w-5 h-5 text-slate-300" />
        </div>
      </div>
    );
  }

  if (responseData && riskConfig) {
    return (
      <div className="flex items-start gap-3 animate-in slide-in-from-left-4 duration-500">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 flex-shrink-0">
          <Shield className="w-5 h-5 text-white" />
        </div>
        <div className="flex-1 max-w-4xl space-y-4">
          <div className={sectionCardClass}>
            <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-center gap-3">
                <div className="grid h-11 w-11 place-items-center rounded-2xl bg-cyan-500/10 text-cyan-300 shadow-sm shadow-cyan-500/10">
                  <ShieldCheck className="w-5 h-5" />
                </div>
                <div>
                  <h2 className="text-white text-lg font-semibold">🚨 Threat Detected</h2>
                  <p className="text-slate-400 text-sm">SOC incident summary for rapid response.</p>
                </div>
              </div>
              <div className="rounded-2xl border border-slate-700/60 bg-slate-900/80 px-4 py-2 text-sm text-slate-300">
                {responseData.severity ? `Severity: ${responseData.severity}` : 'Security incident snapshot'}
              </div>
            </div>

            <div className="mt-6 grid gap-3 sm:grid-cols-3">
              <MetricCard
                title="Attack Type"
                value={attackType}
                icon={<Zap className="w-4 h-4" />}
                accentClass="bg-blue-500/15 text-blue-300"
              />
              <MetricCard
                title="Risk Level"
                value={responseData.risk_level}
                icon={<AlertTriangle className="w-4 h-4" />}
                accentClass={riskConfig.bgColor.replace('/10', '/20') + ' text-white'}
              />
              <MetricCard
                title="Confidence"
                value={`${confidence}%`}
                icon={<BarChart3 className="w-4 h-4" />}
                accentClass="bg-cyan-500/15 text-cyan-300"
              />
            </div>
          </div>

          <div className={sectionCardClass}>
            <div className="flex items-center justify-between gap-4 mb-4">
              <div className="flex items-center gap-2">
                <div className="grid h-10 w-10 place-items-center rounded-2xl bg-slate-700/70 text-slate-200">
                  <BarChart3 className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
                    Confidence Progress
                  </h3>
                  <p className="text-xs text-slate-500">Real-time threat confidence bar.</p>
                </div>
              </div>
              <span className="text-sm font-semibold text-slate-200">{confidence}%</span>
            </div>
            <div className="rounded-full bg-slate-700/80 h-3 overflow-hidden">
              <div className={`${progressFillClass} h-3 rounded-full`} style={{ width: `${confidence}%` }} />
            </div>
          </div>

          <SectionCard
            icon={<AlertTriangle className="w-4 h-4 text-red-400" />}
            title="Immediate Actions"
            accentClass="text-red-400"
          >
            <ul className="space-y-2">
              {responseData.immediate_actions.map((action, i) => (
                <li key={i} className="flex items-start gap-2 text-slate-300">
                  <span className="text-red-400 mt-1 flex-shrink-0">•</span>
                  {action}
                </li>
              ))}
            </ul>
          </SectionCard>

          <SectionCard
            icon={<BookOpen className="w-4 h-4 text-cyan-400" />}
            title="Threat Summary"
            accentClass="text-cyan-400"
          >
            <p>{responseData.overview}</p>
          </SectionCard>

          <SectionCard
            icon={<Zap className="w-4 h-4 text-yellow-400" />}
            title="Root Cause"
            accentClass="text-yellow-400"
          >
            <p>{responseData.root_cause}</p>
          </SectionCard>

          <SectionCard
            icon={<Lock className="w-4 h-4 text-green-400" />}
            title="Prevention"
            accentClass="text-green-400"
          >
            <ul className="space-y-2">
              {responseData.prevention.map((item, i) => (
                <li key={i} className="flex items-start gap-2 text-slate-300">
                  <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                  {item}
                </li>
              ))}
            </ul>
          </SectionCard>

          <SectionCard
            icon={<Zap className="w-4 h-4 text-purple-400" />}
            title="Recommended Tools"
            accentClass="text-purple-400"
          >
            <div className="flex flex-wrap gap-2">
              {responseData.tools.map((tool, i) => (
                <ToolBadge key={i} tool={tool} />
              ))}
            </div>
          </SectionCard>

          {referenceItems.length > 0 && (
            <SectionCard
              icon={<Shield className="w-4 h-4 text-blue-400" />}
              title="References"
              accentClass="text-blue-400"
            >
              <div className="space-y-4">
                {referenceItems.map((reference) => (
                  <div key={reference.label}>
                    <div className="mb-2 text-xs uppercase tracking-[0.24em] text-slate-500">
                      {reference.label}
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {reference.values.map((value, j) => (
                        <span
                          key={j}
                          className="rounded-full bg-slate-700/70 px-3 py-1.5 text-xs text-slate-200 border border-slate-600/50"
                        >
                          {value}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </SectionCard>
          )}

          <SectionCard
            icon={<Shield className="w-4 h-4 text-blue-400" />}
            title="Best Practices"
            accentClass="text-blue-400"
          >
            <ul className="space-y-2">
              {responseData.best_practices.map((practice, i) => (
                <li key={i} className="flex items-start gap-2 text-slate-300">
                  <CheckCircle className="w-4 h-4 text-blue-400 mt-0.5 flex-shrink-0" />
                  {practice}
                </li>
              ))}
            </ul>
          </SectionCard>

          <div className="flex items-center gap-1 justify-end">
            <Clock className="w-3 h-3 text-slate-500" />
            <span className="text-xs text-slate-500">
              {message.timestamp.toLocaleTimeString()}
            </span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="flex items-start gap-3 animate-in slide-in-from-left-4 duration-300">
      <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 flex-shrink-0">
        <Shield className="w-5 h-5 text-white" />
      </div>
      <div className="flex-1 max-w-3xl">
        <div className="bg-slate-800/80 backdrop-blur-sm rounded-2xl rounded-tl-sm p-4 border border-slate-700/50 shadow-lg">
          <p className="text-slate-300 text-sm leading-relaxed">{message.content}</p>
          <div className="flex items-center gap-1 mt-2">
            <Clock className="w-3 h-3 text-slate-500" />
            <span className="text-xs text-slate-500">
              {message.timestamp.toLocaleTimeString()}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

export default memo(ChatMessage);
