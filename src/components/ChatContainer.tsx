import { useRef, useEffect, useState } from 'react';
import { Shield, Send, Bot, User, Clock, Brain, ArrowLeft, RotateCcw } from 'lucide-react';
import type { ChatMessage as ChatMessageType, QuickSuggestion } from '@/types/chat';
import type { MLPredictionResult } from '@/types/detection';
import type { AIAnalysisResponse } from '@/types/chat';
import QuickSuggestions from './QuickSuggestions';
import AnalysisCards from './AnalysisCards';

interface Props {
  detection: MLPredictionResult;
  messages: ChatMessageType[];
  isLoading: boolean;
  onSendMessage: (content: string, type?: 'freeform' | 'quick_reply' | 'xai_request') => void;
  onSuggestionClick: (suggestion: QuickSuggestion) => void;
  onRequestXAI: () => void;
  onNewAnalysis: () => void;
  onBack: () => void;
}

function ChatBubble({ message }: { message: ChatMessageType }) {
  const isUser = message.role === 'user';
  const isLoading = message.type === 'loading';

  if (isLoading) {
    return (
      <div className="flex items-start gap-3 animate-in slide-in-from-left-4 duration-300">
        <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center flex-shrink-0">
          <Bot className="w-4 h-4 text-white animate-pulse" />
        </div>
        <div className="bg-slate-800/80 border border-slate-700/30 rounded-2xl rounded-tl-sm p-4">
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-cyan-400 animate-bounce" />
            <div className="w-2 h-2 rounded-full bg-cyan-400 animate-bounce delay-100" />
            <div className="w-2 h-2 rounded-full bg-cyan-400 animate-bounce delay-200" />
            <span className="text-xs text-slate-400 ml-2">Analyzing...</span>
          </div>
        </div>
      </div>
    );
  }

  if (isUser) {
    return (
      <div className="flex items-start gap-3 justify-end animate-in slide-in-from-right-4 duration-300">
        <div className="bg-gradient-to-r from-cyan-600 to-blue-600 rounded-2xl rounded-tr-sm p-4 max-w-[80%] shadow-lg">
          <p className="text-sm text-white leading-relaxed">{message.content}</p>
          <div className="flex items-center gap-1 mt-2 justify-end">
            <Clock className="w-3 h-3 text-white/50" />
            <span className="text-[10px] text-white/50">
              {message.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
            </span>
          </div>
        </div>
        <div className="w-8 h-8 rounded-lg bg-slate-700 flex items-center justify-center flex-shrink-0">
          <User className="w-4 h-4 text-slate-300" />
        </div>
      </div>
    );
  }

  // Assistant message
  if (message.type === 'initial_analysis' && message.metadata) {
    return (
      <div className="animate-in slide-in-from-left-4 duration-500">
        <AnalysisCards
          detection={{
            ...message.metadata,
            is_attack: true,
            attack_type: message.metadata.attackType || 'Unknown',
            confidence: message.metadata.confidence || 0,
            severity: (message.metadata.severity || 'Low') as MLPredictionResult['severity'],
            risk_level: message.metadata.severity || 'Low',
            features: {},
            timestamp: new Date().toISOString(),
          } as MLPredictionResult}
          analysis={parseAnalysisContent(message.content)}
        />
      </div>
    );
  }

  return (
    <div className="flex items-start gap-3 animate-in slide-in-from-left-4 duration-300">
      <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center flex-shrink-0">
        <Bot className="w-4 h-4 text-white" />
      </div>
      <div className="bg-slate-800/80 border border-slate-700/30 rounded-2xl rounded-tl-sm p-4 max-w-[80%]">
        <div className="prose prose-invert prose-sm max-w-none">
          <div dangerouslySetInnerHTML={{ __html: formatMarkdown(message.content) }} />
        </div>
        {message.metadata?.references && message.metadata.references.length > 0 && (
          <div className="mt-3 pt-3 border-t border-slate-700/30">
            <p className="text-[10px] text-slate-500 mb-1">References:</p>
            <div className="flex flex-wrap gap-1">
              {message.metadata.references.map((ref, i) => (
                <span key={i} className="text-[10px] px-2 py-0.5 bg-slate-700/40 rounded text-slate-400">
                  {ref.source}: {ref.title}
                </span>
              ))}
            </div>
          </div>
        )}
        <div className="flex items-center gap-1 mt-2">
          <Clock className="w-3 h-3 text-slate-500" />
          <span className="text-[10px] text-slate-500">
            {message.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
          </span>
        </div>
      </div>
    </div>
  );
}

function parseAnalysisContent(content: string): AIAnalysisResponse {
  try {
    // Try to parse as JSON first
    const parsed = JSON.parse(content);
    return {
      overview: parsed.overview || parsed.message || content,
      attack_details: parsed.attack_details || '',
      root_cause: parsed.root_cause || '',
      immediate_actions: parsed.immediate_actions || [],
      prevention: parsed.prevention || [],
      tools: parsed.tools || [],
      best_practices: parsed.best_practices || [],
      references: parsed.references || [],
      severity_assessment: parsed.severity_assessment || '',
    };
  } catch {
    // Return content as overview
    return {
      overview: content,
      attack_details: '',
      root_cause: '',
      immediate_actions: [],
      prevention: [],
      tools: [],
      best_practices: [],
      references: [],
      severity_assessment: '',
    };
  }
}

function formatMarkdown(content: string): string {
  return content
    .replace(/^## (.*$)/gim, '<h2 class="text-lg font-bold text-white mb-2">$1</h2>')
    .replace(/^### (.*$)/gim, '<h3 class="text-md font-semibold text-cyan-400 mb-2">$1</h3>')
    .replace(/\*\*(.*?)\*\*/g, '<strong class="text-white">$1</strong>')
    .replace(/\*(.*?)\*/g, '<em class="text-slate-300">$1</em>')
    .replace(/^- (.*$)/gim, '<li class="text-slate-300 text-sm ml-4">$1</li>')
    .replace(/\n/g, '<br/>');
}

export default function ChatContainer({
  detection,
  messages,
  isLoading,
  onSendMessage,
  onSuggestionClick,
  onRequestXAI,
  onNewAnalysis,
  onBack,
}: Props) {
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const [inputValue, setInputValue] = useState('');

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputValue.trim() || isLoading) return;
    onSendMessage(inputValue.trim(), 'freeform');
    setInputValue('');
  };

  return (
    <div className="flex flex-col h-full bg-slate-950/50">
      {/* Chat Header */}
      <div className="flex items-center justify-between px-4 py-3 bg-slate-900/80 border-b border-slate-700/30 backdrop-blur-sm">
        <div className="flex items-center gap-3">
          <button
            onClick={onBack}
            className="w-8 h-8 rounded-lg bg-slate-800 hover:bg-slate-700 flex items-center justify-center transition-colors"
          >
            <ArrowLeft className="w-4 h-4 text-slate-400" />
          </button>
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
            <Shield className="w-4 h-4 text-white" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-white">AI Security Assistant</h3>
            <p className="text-[10px] text-slate-400">
              {detection.attack_type} • {detection.confidence.toFixed(1)}% confidence
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={onRequestXAI}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 rounded-lg text-xs text-slate-300 transition-colors border border-slate-700/30"
            title="Explain this classification"
          >
            <Brain className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Explain AI</span>
          </button>
          <button
            onClick={onNewAnalysis}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 rounded-lg text-xs text-slate-300 transition-colors border border-slate-700/30"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">New Analysis</span>
          </button>
        </div>
      </div>

      {/* Messages Area */}
      <div className="flex-1 overflow-y-auto px-4 py-6 space-y-6">
        {messages.map((message) => (
          <ChatBubble key={message.id} message={message} />
        ))}
        <div ref={messagesEndRef} />
      </div>

      {/* Suggestions + Input Area */}
      <div className="px-4 py-4 bg-slate-900/80 border-t border-slate-700/30 backdrop-blur-sm space-y-4">
        {/* Quick Suggestions */}
        {messages.length <= 2 && (
          <QuickSuggestions
            attackType={detection.attack_type || 'Unknown'}
            onSuggestionClick={onSuggestionClick}
            disabled={isLoading}
          />
        )}

        {/* Free-form Input */}
        <form onSubmit={handleSubmit} className="flex items-center gap-2">
          <div className="flex-1 relative">
            <input
              type="text"
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              placeholder="Ask anything about this attack..."
              className="w-full bg-slate-800/80 border border-slate-700/30 rounded-xl px-4 py-3 text-sm text-white placeholder:text-slate-500 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all"
              disabled={isLoading}
            />
          </div>
          <button
            type="submit"
            disabled={!inputValue.trim() || isLoading}
            className={`w-10 h-10 rounded-xl flex items-center justify-center transition-all ${
              inputValue.trim() && !isLoading
                ? 'bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white shadow-lg shadow-cyan-500/20'
                : 'bg-slate-800 text-slate-500 cursor-not-allowed'
            }`}
          >
            <Send className="w-4 h-4" />
          </button>
        </form>
      </div>
    </div>
  );
}
