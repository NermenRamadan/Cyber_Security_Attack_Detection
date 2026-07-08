import { useState, useCallback, useRef, useEffect } from 'react';
import type { ChatMessage, ChatSession, QuickSuggestion } from '@/types/chat';
import type { MLPredictionResult } from '@/types/detection';
import { getInitialSuggestions } from '@/types/chat';
import { getInitialAnalysis, saveChatHistoryMessage, sendChatMessage } from '@/services/chatApi';
import { useDetectionStore } from '@/stores/agentStore';

function generateId() {
  return crypto.randomUUID();
}

export function useChat() {
  const [session, setSession] = useState<ChatSession | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const sessionRef = useRef<ChatSession | null>(null);
  const store = useDetectionStore();

  useEffect(() => {
    void store.loadHistory('local_user');
  }, [store]);

  // Initialize chat with detection result
  const initializeChat = useCallback((detectionResult: MLPredictionResult) => {
    const newSession: ChatSession = {
      id: generateId(),
      detectionResult,
      messages: [],
      status: 'active',
      createdAt: new Date(),
      lastMessageAt: new Date(),
    };

    sessionRef.current = newSession;
    setSession(newSession);

    // Create initial analysis message
    const initialMessage: ChatMessage = {
      id: generateId(),
      role: 'assistant',
      content: '', // Will be populated by API
      type: 'initial_analysis',
      timestamp: new Date(),
      metadata: {
        attackType: detectionResult.attack_type || 'Unknown',
        confidence: detectionResult.confidence ?? undefined,
        severity: detectionResult.severity,
      },
      suggestions: getInitialSuggestions(detectionResult.attack_type || 'Unknown'),
    };

    setMessages([initialMessage]);

    // Fetch initial analysis from AI
    void fetchInitialAnalysis(newSession, detectionResult, initialMessage.id);

    return newSession;
  }, []);

  const fetchInitialAnalysis = async (
    chatSession: ChatSession,
    detection: MLPredictionResult,
    messageId: string
  ) => {
    setIsLoading(true);

    try {
      const analysis = await getInitialAnalysis(
        detection.attack_type || 'Unknown',
        detection.confidence ?? 0,
        detection.severity,
        chatSession.id
      );

      setMessages(prev =>
        prev.map(msg =>
          msg.id === messageId
            ? {
                ...msg,
                content: analysis.overview || 'Analysis is ready.',
                metadata: {
                  ...msg.metadata,
                  references: analysis.references,
                  actionItems: analysis.immediate_actions,
                },
                suggestions: getInitialSuggestions(detection.attack_type || 'Unknown'),
              }
            : msg
        )
      );
    } catch (err) {
      // Fallback: use mock analysis
      const fallbackContent = generateFallbackAnalysis(detection);
      setMessages(prev =>
        prev.map(msg =>
          msg.id === messageId
            ? { ...msg, content: fallbackContent }
            : msg
        )
      );
    } finally {
      setIsLoading(false);
    }
  };

  const sendMessage = useCallback(async (content: string, type: 'freeform' | 'quick_reply' | 'xai_request' = 'freeform') => {
    if (!sessionRef.current) return;

    const userMessage: ChatMessage = {
      id: generateId(),
      role: 'user',
      content,
      type: type === 'xai_request' ? 'freeform' : type,
      timestamp: new Date(),
    };

    const loadingMessage: ChatMessage = {
      id: generateId(),
      role: 'assistant',
      content: '',
      type: 'loading',
      timestamp: new Date(),
    };

    setMessages(prev => [...prev, userMessage, loadingMessage]);
    setIsLoading(true);

    try {
      const detection = sessionRef.current.detectionResult;
      const previousMessages = messages.slice(-10).map(m => ({
        role: m.role,
        content: m.content,
      }));
      const chatType: 'initial_analysis' | 'freeform' | 'xai_request' = type === 'xai_request' ? 'xai_request' : 'freeform';

      await store.saveMessage({
        user_id: 'local_user',
        role: 'user',
        content,
        session_id: sessionRef.current.id,
      });

      const response = await sendChatMessage({
        message: content,
        session_id: sessionRef.current.id,
        context: {
          attack_type: detection.attack_type ?? 'Unknown',
          confidence: detection.confidence ?? 0,
          severity: detection.severity,
          features: detection.features,
          previous_messages: [...previousMessages, { role: 'user', content }],
        },
        type: chatType,
      });

      await saveChatHistoryMessage({
        user_id: 'local_user',
        role: 'assistant',
        content: response.message,
        session_id: sessionRef.current.id,
      });

      setMessages(prev =>
        prev.map(msg =>
          msg.id === loadingMessage.id
            ? {
                ...msg,
                id: generateId(),
                content: response.message || 'No response received.',
                type: (chatType === 'xai_request' ? 'xai_explanation' : 'freeform') as ChatMessage['type'],
                metadata: {
                  references: response.references,
                  actionItems: response.metadata?.action_items,
                },
                suggestions: response.suggestions || [],
              }
            : msg
        )
      );
    } catch (err) {
      setMessages(prev =>
        prev.map(msg =>
          msg.id === loadingMessage.id
            ? {
                ...msg,
                content: err instanceof Error ? err.message : 'I apologize, but I am unable to process your request right now.',
                type: 'error',
              }
            : msg
        )
      );
    } finally {
      setIsLoading(false);
    }
  }, [messages]);

  const sendQuickSuggestion = useCallback((suggestion: QuickSuggestion) => {
    return sendMessage(suggestion.prompt, 'quick_reply');
  }, [sendMessage]);

  const requestXAI = useCallback(() => {
    if (!sessionRef.current) return;
    const detection = sessionRef.current.detectionResult;
    return sendMessage(
      `Explain why the XGBoost model classified this as ${detection.attack_type} with ${detection.confidence}% confidence. Show the most important features.`,
      'xai_request'
    );
  }, [sendMessage]);

  const endSession = useCallback(() => {
    if (sessionRef.current) {
      setSession(prev => prev ? { ...prev, status: 'ended' } : null);
      sessionRef.current = null;
    }
  }, []);

  return {
    session,
    messages,
    isLoading,
    initializeChat,
    sendMessage,
    sendQuickSuggestion,
    requestXAI,
    endSession,
    hasSession: !!session,
    isActive: session?.status === 'active',
  };
}

// Fallback analysis when backend is unavailable
function generateFallbackAnalysis(detection: MLPredictionResult): string {
  return `## 🎯 ${detection.attack_type} Attack Detected

**Confidence:** ${detection.confidence}%  
**Severity:** ${detection.severity}  
**Protocol:** ${detection.features?.protocol || 'N/A'}  
**Target Port:** ${detection.features?.dest_port || 'N/A'}

### Overview
The XGBoost model has detected a **${detection.attack_type}** attack pattern in the analyzed network traffic with ${detection.confidence}% confidence.

### Key Indicators
- Protocol: ${detection.features?.protocol || 'Unknown'}
- Packet Size: ${detection.features?.length || 'N/A'} bytes
- TCP Flags: ${detection.features?.tcp_flags || 'N/A'}
- Time Delta: ${detection.features?.deltatime_new || 'N/A'}ms

### Immediate Actions
1. Review firewall logs for ${detection.features?.source_ip || 'source IP'}
2. Check target service on port ${detection.features?.dest_port || 'N/A'}
3. Monitor for additional attack patterns
4. Consider blocking suspicious traffic temporarily

*Note: Connect to the backend for detailed AI-powered analysis with RAG knowledge base.*`;
}
