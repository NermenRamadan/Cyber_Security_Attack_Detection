import { useMemo } from 'react';
import { MessageSquare, Shield, BookOpen, Wrench, Globe, BarChart3 } from 'lucide-react';
import type { QuickSuggestion } from '@/types/chat';
import { getInitialSuggestions } from '@/types/chat';

interface Props {
  attackType: string;
  onSuggestionClick: (suggestion: QuickSuggestion) => void;
  disabled?: boolean;
}

const categoryIcons = {
  explanation: BookOpen,
  mitigation: Shield,
  technical: BarChart3,
  tools: Wrench,
  learning: Globe,
};

const categoryColors = {
  explanation: 'border-cyan-500/30 hover:border-cyan-500/60 text-cyan-300',
  mitigation: 'border-red-500/30 hover:border-red-500/60 text-red-300',
  technical: 'border-purple-500/30 hover:border-purple-500/60 text-purple-300',
  tools: 'border-orange-500/30 hover:border-orange-500/60 text-orange-300',
  learning: 'border-green-500/30 hover:border-green-500/60 text-green-300',
};

export default function QuickSuggestions({ attackType, onSuggestionClick, disabled }: Props) {
  const suggestions = useMemo(() => getInitialSuggestions(attackType), [attackType]);

  return (
    <div className="w-full">
      <p className="text-xs text-slate-500 mb-3 flex items-center gap-2">
        <MessageSquare className="w-3 h-3" />
        Quick Suggestions
      </p>
      <div className="flex flex-wrap gap-2">
        {suggestions.map((suggestion) => {
          const Icon = categoryIcons[suggestion.category];
          const colorClass = categoryColors[suggestion.category];

          return (
            <button
              key={suggestion.id}
              onClick={() => !disabled && onSuggestionClick(suggestion)}
              disabled={disabled}
              className={`inline-flex items-center gap-2 px-3 py-2 rounded-xl border bg-slate-800/60 backdrop-blur-sm text-xs font-medium transition-all duration-200 hover:scale-[1.02] hover:shadow-lg active:scale-[0.98] ${colorClass} ${
                disabled ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">{suggestion.label}</span>
              <span className="sm:hidden">{suggestion.icon} {suggestion.label.split(' ').slice(0, 2).join(' ')}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
