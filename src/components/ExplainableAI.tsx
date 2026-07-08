import { Brain, X, TrendingUp, TrendingDown, Info } from 'lucide-react';
import type { SHAPExplanation } from '@/types/detection';

interface Props {
  explanation: SHAPExplanation | null;
  isOpen: boolean;
  onClose: () => void;
}

export default function ExplainableAI({ explanation, isOpen, onClose }: Props) {
  if (!isOpen || !explanation) return null;

  const maxValue = Math.max(
    ...explanation.features.map(f => Math.abs(f.value)),
    0.001
  );

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-slate-900 border border-slate-700/50 rounded-2xl p-6 max-w-2xl w-full mx-4 shadow-2xl max-h-[80vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-purple-500 to-pink-600 flex items-center justify-center">
              <Brain className="w-5 h-5 text-white" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white">Explainable AI</h2>
              <p className="text-xs text-slate-400">Why did the model make this prediction?</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="w-8 h-8 rounded-lg bg-slate-800 hover:bg-slate-700 flex items-center justify-center transition-colors"
          >
            <X className="w-4 h-4 text-slate-400" />
          </button>
        </div>

        {/* Prediction Summary */}
        <div className="bg-slate-800/50 rounded-xl p-4 border border-slate-700/30 mb-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs text-slate-400">Base Value</p>
              <p className="text-lg font-bold text-slate-300">{(explanation.base_value * 100).toFixed(1)}%</p>
            </div>
            <div className="flex-1 mx-4 h-px bg-slate-700" />
            <div className="text-center">
              <p className="text-xs text-slate-400">+ Features Impact</p>
              <p className="text-lg font-bold text-cyan-400">
                +{((explanation.predicted_value - explanation.base_value) * 100).toFixed(1)}%
              </p>
            </div>
            <div className="flex-1 mx-4 h-px bg-slate-700" />
            <div>
              <p className="text-xs text-slate-400">Final Prediction</p>
              <p className="text-lg font-bold text-red-400">{(explanation.predicted_value * 100).toFixed(1)}%</p>
            </div>
          </div>
        </div>

        {/* Feature Importance Chart */}
        <div className="space-y-3">
          <h3 className="text-sm font-semibold text-slate-300 flex items-center gap-2">
            <Info className="w-4 h-4 text-cyan-400" />
            Feature Importance (SHAP Values)
          </h3>

          {explanation.features.map((feature, i) => {
            const percentage = (Math.abs(feature.value) / maxValue) * 100;
            const isPositive = feature.impact === 'positive';

            return (
              <div key={i} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-300 flex items-center gap-2">
                    {isPositive ? (
                      <TrendingUp className="w-3 h-3 text-red-400" />
                    ) : (
                      <TrendingDown className="w-3 h-3 text-green-400" />
                    )}
                    {feature.feature}
                  </span>
                  <span className={`font-mono ${isPositive ? 'text-red-400' : 'text-green-400'}`}>
                    {feature.value > 0 ? '+' : ''}{feature.value.toFixed(4)}
                  </span>
                </div>
                <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all duration-500 ${
                      isPositive ? 'bg-red-500' : 'bg-green-500'
                    }`}
                    style={{ width: `${Math.max(percentage, 5)}%` }}
                  />
                </div>
                <p className="text-[10px] text-slate-500">{feature.description}</p>
              </div>
            );
          })}
        </div>

        {/* Top Positive Features */}
        {explanation.top_positive.length > 0 && (
          <div className="mt-6 bg-red-500/5 border border-red-500/20 rounded-xl p-4">
            <h4 className="text-xs font-semibold text-red-400 mb-2 flex items-center gap-2">
              <TrendingUp className="w-3 h-3" />
              Top Indicators (Increased Risk)
            </h4>
            <ul className="space-y-1">
              {explanation.top_positive.slice(0, 3).map((f, i) => (
                <li key={i} className="text-xs text-slate-300 flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-red-400" />
                  {f.feature}: +{f.value.toFixed(4)}
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Top Negative Features */}
        {explanation.top_negative.length > 0 && (
          <div className="mt-3 bg-green-500/5 border border-green-500/20 rounded-xl p-4">
            <h4 className="text-xs font-semibold text-green-400 mb-2 flex items-center gap-2">
              <TrendingDown className="w-3 h-3" />
              Indicators Against (Decreased Risk)
            </h4>
            <ul className="space-y-1">
              {explanation.top_negative.slice(0, 3).map((f, i) => (
                <li key={i} className="text-xs text-slate-300 flex items-center gap-2">
                  <span className="w-1.5 h-1.5 rounded-full bg-green-400" />
                  {f.feature}: {f.value.toFixed(4)}
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Close Button */}
        <button
          onClick={onClose}
          className="w-full mt-6 py-3 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-xl transition-colors text-sm"
        >
          Close Explanation
        </button>
      </div>
    </div>
  );
}
