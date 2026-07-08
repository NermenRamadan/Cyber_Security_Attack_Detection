import { Shield, AlertTriangle, Zap, Lock, Wrench, BookOpen, CheckCircle, TrendingUp, Activity } from 'lucide-react';
import type { AIAnalysisResponse } from '@/types/chat';
import type { MLPredictionResult } from '@/types/detection';
import { getRiskConfig, getSeverityConfig } from '@/types/detection';

interface Props {
  detection: MLPredictionResult;
  analysis: AIAnalysisResponse;
}

export default function AnalysisCards({ detection, analysis }: Props) {
  const riskConfig = getRiskConfig(detection.confidence);
  const sevConfig = getSeverityConfig(detection.severity);

  return (
    <div className="space-y-4 w-full">
      {/* Risk Summary Card */}
      <div className={`${riskConfig.bgColor} border ${riskConfig.borderColor} rounded-2xl p-5 backdrop-blur-sm`}>
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <div className={`w-10 h-10 rounded-xl ${riskConfig.bgColor} flex items-center justify-center`}>
              <Shield className={`w-5 h-5 ${riskConfig.color}`} />
            </div>
            <div>
              <h3 className={`text-lg font-bold ${riskConfig.color}`}>
                {detection.attack_type}
              </h3>
              <p className="text-xs text-slate-400">Detected Attack</p>
            </div>
          </div>
          <span className={`inline-flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-semibold border ${sevConfig.color}`}>
            {sevConfig.icon} {detection.severity}
          </span>
        </div>

        {/* Metrics Grid */}
        <div className="grid grid-cols-3 gap-3">
          <div className="bg-slate-900/50 rounded-xl p-3 text-center">
            <TrendingUp className="w-4 h-4 text-cyan-400 mx-auto mb-1" />
            <p className="text-lg font-bold text-white">{detection.confidence.toFixed(1)}%</p>
            <p className="text-[10px] text-slate-400">Confidence</p>
          </div>
          <div className="bg-slate-900/50 rounded-xl p-3 text-center">
            <Activity className="w-4 h-4 text-orange-400 mx-auto mb-1" />
            <p className="text-lg font-bold text-white">{detection.features?.protocol || 'N/A'}</p>
            <p className="text-[10px] text-slate-400">Protocol</p>
          </div>
          <div className="bg-slate-900/50 rounded-xl p-3 text-center">
            <Zap className="w-4 h-4 text-yellow-400 mx-auto mb-1" />
            <p className="text-lg font-bold text-white">{detection.features?.dest_port || 'N/A'}</p>
            <p className="text-[10px] text-slate-400">Target Port</p>
          </div>
        </div>

        {/* Confidence Bar */}
        <div className="mt-4">
          <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
            <div
              className={`h-full ${riskConfig.progressColor} rounded-full transition-all duration-1000`}
              style={{ width: `${detection.confidence}%` }}
            />
          </div>
        </div>
      </div>

      {/* Overview Card */}
      <div className="bg-slate-800/60 border border-slate-700/30 rounded-2xl p-5 backdrop-blur-sm">
        <div className="flex items-center gap-2 mb-3">
          <BookOpen className="w-4 h-4 text-cyan-400" />
          <h4 className="text-sm font-semibold text-cyan-400 uppercase tracking-wider">Overview</h4>
        </div>
        <p className="text-sm text-slate-300 leading-relaxed">{analysis.overview}</p>
      </div>

      {/* Attack Details */}
      <div className="bg-slate-800/60 border border-slate-700/30 rounded-2xl p-5 backdrop-blur-sm">
        <div className="flex items-center gap-2 mb-3">
          <AlertTriangle className="w-4 h-4 text-orange-400" />
          <h4 className="text-sm font-semibold text-orange-400 uppercase tracking-wider">Attack Details</h4>
        </div>
        <p className="text-sm text-slate-300 leading-relaxed">{analysis.attack_details}</p>
      </div>

      {/* Root Cause */}
      <div className="bg-slate-800/60 border border-slate-700/30 rounded-2xl p-5 backdrop-blur-sm">
        <div className="flex items-center gap-2 mb-3">
          <Zap className="w-4 h-4 text-yellow-400" />
          <h4 className="text-sm font-semibold text-yellow-400 uppercase tracking-wider">Root Cause</h4>
        </div>
        <p className="text-sm text-slate-300 leading-relaxed">{analysis.root_cause}</p>
      </div>

      {/* Immediate Actions */}
      <div className="bg-slate-800/60 border border-red-500/20 rounded-2xl p-5 backdrop-blur-sm">
        <div className="flex items-center gap-2 mb-3">
          <AlertTriangle className="w-4 h-4 text-red-400" />
          <h4 className="text-sm font-semibold text-red-400 uppercase tracking-wider">Immediate Actions</h4>
        </div>
        <ul className="space-y-2">
          {analysis.immediate_actions.map((action, i) => (
            <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
              <span className="text-red-400 mt-0.5 flex-shrink-0">{i + 1}.</span>
              {action}
            </li>
          ))}
        </ul>
      </div>

      {/* Prevention */}
      <div className="bg-slate-800/60 border border-green-500/20 rounded-2xl p-5 backdrop-blur-sm">
        <div className="flex items-center gap-2 mb-3">
          <Lock className="w-4 h-4 text-green-400" />
          <h4 className="text-sm font-semibold text-green-400 uppercase tracking-wider">Prevention</h4>
        </div>
        <ul className="space-y-2">
          {analysis.prevention.map((item, i) => (
            <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
              <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
              {item}
            </li>
          ))}
        </ul>
      </div>

      {/* Tools */}
      <div className="bg-slate-800/60 border border-purple-500/20 rounded-2xl p-5 backdrop-blur-sm">
        <div className="flex items-center gap-2 mb-3">
          <Wrench className="w-4 h-4 text-purple-400" />
          <h4 className="text-sm font-semibold text-purple-400 uppercase tracking-wider">Recommended Tools</h4>
        </div>
        <div className="flex flex-wrap gap-2">
          {analysis.tools.map((tool, i) => (
            <span
              key={i}
              className="px-3 py-1.5 bg-slate-700/60 rounded-lg text-slate-300 text-xs border border-slate-600/50 hover:border-purple-500/30 transition-colors"
            >
              {tool}
            </span>
          ))}
        </div>
      </div>

      {/* Best Practices */}
      <div className="bg-slate-800/60 border border-blue-500/20 rounded-2xl p-5 backdrop-blur-sm">
        <div className="flex items-center gap-2 mb-3">
          <Shield className="w-4 h-4 text-blue-400" />
          <h4 className="text-sm font-semibold text-blue-400 uppercase tracking-wider">Best Practices</h4>
        </div>
        <ul className="space-y-2">
          {analysis.best_practices.map((practice, i) => (
            <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
              <CheckCircle className="w-4 h-4 text-blue-400 mt-0.5 flex-shrink-0" />
              {practice}
            </li>
          ))}
        </ul>
      </div>

      {/* References */}
      {analysis.references && analysis.references.length > 0 && (
        <div className="bg-slate-800/40 border border-slate-700/20 rounded-2xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <BookOpen className="w-4 h-4 text-slate-400" />
            <h4 className="text-sm font-semibold text-slate-400 uppercase tracking-wider">References</h4>
          </div>
          <div className="flex flex-wrap gap-2">
            {analysis.references.map((ref, i) => (
              <span
                key={i}
                className="px-2 py-1 bg-slate-700/40 rounded text-xs text-slate-400 border border-slate-600/30"
              >
                {ref.source}: {ref.title}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

