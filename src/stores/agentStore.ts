// CYBERSHIELD AI — AGENT ZUSTAND STORE
// Manages agent state: current detection, chat history, analysis, sessions.
// Persist: localStorage for offline resilience.
// Future: Sync with backend for multi-device support.

import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';
import type { DetectionResult, ChatMessage, AnalysisData, AgentSession } from '@/types/agent';

//Store State 
interface AgentStoreState {
  // Current active detection
  currentDetection: DetectionResult | null;

  // Chat messages for current session
  messages: ChatMessage[];

  // AI-generated analysis
  analysis: AnalysisData | null;
  isAnalysisLoading: boolean;

  // Session management
  sessionId: string;
  sessions: AgentSession[];

  // UI state
  isChatLoading: boolean;
  activeSuggestionCategory: string | null;
}

// Store Actions 
interface AgentStoreActions {
  // Detection
  setCurrentDetection: (detection: DetectionResult | null) => void;
  clearCurrentDetection: () => void;

  // Chat
  addMessage: (message: ChatMessage) => void;
  updateLastMessage: (content: string) => void;
  setMessages: (messages: ChatMessage[]) => void;
  clearChat: () => void;

  // Analysis
  setAnalysis: (analysis: AnalysisData | null) => void;
  setAnalysisLoading: (loading: boolean) => void;

  // Session
  setSessionId: (id: string) => void;
  createSession: (detection: DetectionResult) => string;
  loadSession: (sessionId: string) => boolean;
  deleteSession: (sessionId: string) => void;

  // UI
  setChatLoading: (loading: boolean) => void;
  setActiveSuggestionCategory: (category: string | null) => void;

  // Reset
  reset: () => void;
}

// Initial State 
const initialState: AgentStoreState = {
  currentDetection: null,
  messages: [
    {
      id: 'welcome',
      role: 'assistant',
      content: 'Hi — I\'m your SOC analyst agent. I\'ve analyzed the detected attack. Ask me anything about it, or use the suggestions below.',
      timestamp: new Date().toISOString(),
    },
  ],
  analysis: null,
  isAnalysisLoading: false,
  sessionId: '',
  sessions: [],
  isChatLoading: false,
  activeSuggestionCategory: null,
};

// Store Factory 
export const useAgentStore = create<AgentStoreState & AgentStoreActions>()(
  persist(
    (set, get) => ({
      ...initialState,

      //  Detection 
      setCurrentDetection: (detection) => {
        set({ currentDetection: detection });
        if (detection) {
          // Auto-create session when detection is set
          get().createSession(detection);
        }
      },

      clearCurrentDetection: () => {
        set({ currentDetection: null });
      },

      // Chat 
      addMessage: (message) => {
        set((state) => ({
          messages: [...state.messages, message],
        }));
      },

      updateLastMessage: (content) => {
        set((state) => ({
          messages: state.messages.map((m, i) =>
            i === state.messages.length - 1 ? { ...m, content } : m
          ),
        }));
      },

      setMessages: (messages) => {
        set({ messages });
      },

      clearChat: () => {
        set({
          messages: [
            {
              id: 'welcome',
              role: 'assistant',
              content: 'Chat cleared. How can I help you with this attack?',
              timestamp: new Date().toISOString(),
            },
          ],
        });
      },

      // Analysis 
      setAnalysis: (analysis) => {
        set({ analysis });
      },

      setAnalysisLoading: (loading) => {
        set({ isAnalysisLoading: loading });
      },

      //  Session 
      setSessionId: (id) => {
        set({ sessionId: id });
      },

      createSession: (detection) => {
        const sessionId = crypto.randomUUID();
        const session: AgentSession = {
          sessionId,
          detectionId: crypto.randomUUID(),
          attackType: detection.attack_type,
          severity: detection.severity,
          confidence: detection.confidence ?? 0,
          sourceIp: detection.features.source_ip,
          protocol: detection.features.protocol,
          timestamp: new Date().toISOString(),
          messages: [],
          analysis: null,
          isAnalysisLoading: false,
          isChatLoading: false,
        };

        set((state) => ({
          sessionId,
          sessions: [session, ...state.sessions].slice(0, 50), // Keep last 50 sessions
        }));

        return sessionId;
      },

      loadSession: (sessionId) => {
        const session = get().sessions.find((s) => s.sessionId === sessionId);
        if (!session) return false;

        set({
          sessionId: session.sessionId,
          messages: session.messages,
          analysis: session.analysis,
        });

        return true;
      },

      deleteSession: (sessionId) => {
        set((state) => ({
          sessions: state.sessions.filter((s) => s.sessionId !== sessionId),
          sessionId: state.sessionId === sessionId ? '' : state.sessionId,
        }));
      },

      // UI 
      setChatLoading: (loading) => {
        set({ isChatLoading: loading });
      },

      setActiveSuggestionCategory: (category) => {
        set({ activeSuggestionCategory: category });
      },

      // Reset 
      reset: () => {
        set(initialState);
      },
    }),
    {
      name: 'cybershield-agent-storage',
      storage: createJSONStorage(() => localStorage),
      partialize: (state) => ({
        // Only persist these fields
        sessions: state.sessions,
        sessionId: state.sessionId,
        currentDetection: state.currentDetection,
        messages: state.messages,
        analysis: state.analysis,
      }),
    }
  )
);

// Selectors 
export const selectCurrentDetection = (state: AgentStoreState & AgentStoreActions) =>
  state.currentDetection;

export const selectMessages = (state: AgentStoreState & AgentStoreActions) =>
  state.messages;

export const selectAnalysis = (state: AgentStoreState & AgentStoreActions) =>
  state.analysis;

export const selectIsAnalysisLoading = (state: AgentStoreState & AgentStoreActions) =>
  state.isAnalysisLoading;

export const selectSessionId = (state: AgentStoreState & AgentStoreActions) =>
  state.sessionId;

export const selectSessions = (state: AgentStoreState & AgentStoreActions) =>
  state.sessions;