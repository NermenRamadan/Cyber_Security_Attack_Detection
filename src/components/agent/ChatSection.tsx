// ═══════════════════════════════════════════════════════════════════════════════
// CYBERSHIELD AI — CHAT SECTION WITH CONVERSATION MEMORY
// ═══════════════════════════════════════════════════════════════════════════════
// Free-form chat with the AI Security Assistant.
// Features: Auto-scroll, typing indicator, markdown rendering, copy button.
// Memory: Messages synced with Zustand store + backend.
// ═══════════════════════════════════════════════════════════════════════════════

import { useState, useRef, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Send,
  Bot,
  User,
  Loader2,
  Copy,
  Check,
  Trash2,
  Clock,
} from 'lucide-react';
import { useAgentStore } from '@/stores/agentStore';
import { sendChatMessage, saveMessageToBackend } from '@/services/agentService';
import type { ChatMessage } from '@/types/agent';

interface ChatSectionProps {
  className?: string;
}

// ── Message Bubble Component ───────────────────────────────────────────────────
function MessageBubble({ message, isLast }: { message: ChatMessage; isLast: boolean }) {
  const [copied, setCopied] = useState(false);
  const isUser = message.role === 'user';
  const isLoading = message.isLoading;

  const handleCopy = async () => {
    await navigator.clipboard.writeText(message.content);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className={`flex gap-3 ${isUser ? 'flex-row-reverse' : ''}`}
    >
      {/* Avatar */}
      <div
        className={`shrink-0 w-8 h-8 rounded-lg flex items-center justify-center ${
          isUser
            ? 'bg-primary/20 text-primary'
            : 'bg-accent/20 text-accent'
        }`}
      >
        {isUser ? <User className="h-4 w-4" /> : <Bot className="h-4 w-4" />}
      </div>

      {/* Content */}
      <div className={`flex flex-col max-w-[80%] ${isUser ? 'items-end' : 'items-start'}`}>
        <div
          className={`relative group rounded-2xl px-4 py-3 ${
            isUser
              ? 'bg-primary/15 text-foreground'
              : 'bg-white/5 border border-white/10 text-foreground'
          }`}
        >
          {/* Loading State */}
          {isLoading ? (
            <div className="flex items-center gap-2">
              <Loader2 className="h-4 w-4 animate-spin text-primary" />
              <span className="text-sm text-muted-foreground">SentinelAI is thinking...</span>
            </div>
          ) : (
            <div className="text-sm leading-relaxed whitespace-pre-wrap">
              {message.content}
            </div>
          )}

          {/* Copy Button */}
          {!isLoading && message.content && (
            <button
              onClick={handleCopy}
              className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity p-1 rounded-md hover:bg-white/10"
              title="Copy message"
            >
              {copied ? (
                <Check className="h-3.5 w-3.5 text-green-400" />
              ) : (
                <Copy className="h-3.5 w-3.5 text-muted-foreground" />
              )}
            </button>
          )}
        </div>

        {/* Timestamp */}
        <span className="text-[10px] text-muted-foreground mt-1 px-1">
          {new Date(message.timestamp).toLocaleTimeString([], {
            hour: '2-digit',
            minute: '2-digit',
          })}
        </span>
      </div>
    </motion.div>
  );
}

// ── Main Chat Section ──────────────────────────────────────────────────────────
export function ChatSection({ className = '' }: ChatSectionProps) {
  const { messages, addMessage, updateLastMessage, setChatLoading, isChatLoading, sessionId } =
    useAgentStore();

  const [input, setInput] = useState('');
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Auto-scroll to bottom
  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: 'smooth' });
  }, [messages]);

  // Send message handler
  const handleSend = useCallback(
    async (text?: string) => {
      const content = (text ?? input).trim();
      if (!content || isChatLoading) return;

      setInput('');
      setChatLoading(true);

      // Add user message
      const userMsg: ChatMessage = {
        id: crypto.randomUUID(),
        role: 'user',
        content,
        timestamp: new Date().toISOString(),
      };
      addMessage(userMsg);

      // Save to backend (async, non-blocking)
      saveMessageToBackend(userMsg, 'local_user', sessionId);

      // Add loading placeholder
      const loadingMsg: ChatMessage = {
        id: 'loading',
        role: 'assistant',
        content: '',
        timestamp: new Date().toISOString(),
        isLoading: true,
      };
      addMessage(loadingMsg);

      try {
        // Send to AI
        const response = await sendChatMessage(
          [...messages, userMsg],
          'chat',
          [],
          'local_user',
          sessionId
        );

        // Replace loading with actual response
        const aiMsg: ChatMessage = {
          id: crypto.randomUUID(),
          role: 'assistant',
          content: response.message,
          timestamp: response.timestamp,
        };

        // Remove loading and add AI message
        setChatLoading(false);
        updateLastMessage(aiMsg.content);

        // Save AI response to backend
        saveMessageToBackend(aiMsg, 'local_user', sessionId);
      } catch (err) {
        console.error('Chat error:', err);
        setChatLoading(false);
        updateLastMessage(
          'I apologize, but I encountered an error processing your request. Please try again.'
        );
      }
    },
    [input, isChatLoading, messages, sessionId, addMessage, updateLastMessage, setChatLoading]
  );

  // Handle Enter key
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  // Clear chat
  const handleClear = () => {
    if (confirm('Clear this conversation?')) {
      useAgentStore.getState().clearChat();
    }
  };

  return (
    <div className={`flex flex-col ${className}`}>
      {/* Chat Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Bot className="h-4 w-4 text-primary" />
          <h3 className="text-sm font-semibold text-foreground">Conversation</h3>
          <span className="text-xs text-muted-foreground">({messages.length} messages)</span>
        </div>
        <button
          onClick={handleClear}
          className="p-1.5 rounded-lg hover:bg-white/10 text-muted-foreground hover:text-red-400 transition-colors"
          title="Clear chat"
        >
          <Trash2 className="h-3.5 w-3.5" />
        </button>
      </div>

      {/* Messages Area */}
      <div
        ref={scrollRef}
        className="flex-1 min-h-[300px] max-h-[500px] overflow-y-auto space-y-4 p-4 rounded-xl bg-white/[0.02] border border-white/10"
      >
        <AnimatePresence>
          {messages.map((msg, index) => (
            <MessageBubble
              key={msg.id}
              message={msg}
              isLast={index === messages.length - 1}
            />
          ))}
        </AnimatePresence>
      </div>

      {/* Input Area */}
      <div className="mt-3 flex items-center gap-2">
        <div className="flex-1 relative">
          <input
            ref={inputRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ask about this attack..."
            disabled={isChatLoading}
            className="w-full rounded-xl border border-white/10 bg-white/5 px-4 py-3 pr-10 text-sm text-foreground placeholder:text-muted-foreground outline-none focus:border-primary/60 focus:bg-white/[0.07] transition-all disabled:opacity-50"
          />
          {input.length > 0 && (
            <span className="absolute right-3 top-1/2 -translate-y-1/2 text-[10px] text-muted-foreground">
              {input.length}
            </span>
          )}
        </div>
        <motion.button
          whileHover={{ scale: 1.05 }}
          whileTap={{ scale: 0.95 }}
          onClick={() => handleSend()}
          disabled={isChatLoading || !input.trim()}
          className="shrink-0 w-11 h-11 rounded-xl bg-primary text-primary-foreground flex items-center justify-center hover:bg-primary/90 disabled:opacity-40 disabled:hover:scale-100 transition-all"
        >
          {isChatLoading ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <Send className="h-4 w-4" />
          )}
        </motion.button>
      </div>

      {/* Session Info */}
      {sessionId && (
        <div className="mt-2 flex items-center gap-1.5 text-[10px] text-muted-foreground/60">
          <Clock className="h-3 w-3" />
          <span>Session: {sessionId.slice(0, 8)}...</span>
        </div>
      )}
    </div>
  );
}