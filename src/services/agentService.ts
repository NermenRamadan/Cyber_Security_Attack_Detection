
// CYBERSHIELD AI — AGENT SERVICE LAYER

// Handles all API communication for the Agent page.
// Unified response format: { success, data, message, timestamp }

import type {
  ApiResponse,
  AgentApiResponse,
  ChatHistoryResponse,
  ChatMessage,
  DetectionResult,
} from '@/types/agent';

type AgentMessagePayload = Pick<ChatMessage, 'role' | 'content'>;

const API_BASE = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

// Helper: Handle API Response 
async function handleResponse<T>(response: Response): Promise<ApiResponse<T>> {
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}));
    throw new Error(errorData.message || `HTTP ${response.status}: ${response.statusText}`);
  }
  return response.json();
}

// Send Chat Message to AI Agent
export async function sendChatMessage(
  messages: ChatMessage[],
  mode: 'chat' | 'summary' = 'chat',
  logs: unknown[] = [],
  userId: string = 'local_user',
  sessionId?: string
): Promise<AgentApiResponse> {
  const response = await fetch(`${API_BASE}/api/agent`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      messages: messages.map((m) => ({ role: m.role, content: m.content })),
      mode,
      logs,
      user_id: userId,
      session_id: sessionId,
    }),
  });

  const data = await handleResponse<AgentApiResponse>(response);
  return data.data;
}

// Generate Initial Analysis 
export async function generateInitialAnalysis(
  detection: DetectionResult,
  logs: unknown[] = []
): Promise<AgentApiResponse> {
  const contextMessage: ChatMessage = {
    id: crypto.randomUUID(),
    role: 'user',
    content: `Analyze this ${detection.attack_type} attack with ${detection.confidence?.toFixed(1)}% confidence. 
Source: ${detection.features.source_ip}, Protocol: ${detection.features.protocol}.
Provide: overview, root cause, immediate actions, prevention, tools, best practices.`,
    timestamp: new Date().toISOString(),
  };

  return sendChatMessage([contextMessage], 'summary', logs);
}

// Save Message to Backend 
export async function saveMessageToBackend(
  message: ChatMessage,
  userId: string = 'local_user',
  sessionId?: string
): Promise<void> {
  try {
    await fetch(`${API_BASE}/api/chat/message`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user_id: userId,
        role: message.role,
        content: message.content,
        session_id: sessionId,
      }),
    });
  } catch (err) {
    console.warn('Failed to save message to backend:', err);
    // Non-blocking: message is already in localStorage via Zustand persist
  }
}

// Fetch Chat History 
export async function fetchChatHistory(
  userId: string = 'local_user',
  sessionId?: string
): Promise<ChatMessage[]> {
  const params = new URLSearchParams({ user_id: userId });
  if (sessionId) params.append('session_id', sessionId);

  const response = await fetch(`${API_BASE}/api/chat/history?${params}`);
  const data = await handleResponse<ChatHistoryResponse[]>(response);

  return data.data.map((msg) => ({
    id: msg.id,
    role: msg.role as 'user' | 'assistant' | 'system',
    content: msg.content,
    timestamp: msg.created_at,
    sessionId: msg.session_id,
  }));
}

// Clear Chat History 
export async function clearChatHistory(
  userId: string = 'local_user',
  sessionId?: string
): Promise<void> {
  const params = new URLSearchParams({ user_id: userId });
  if (sessionId) params.append('session_id', sessionId);

  await fetch(`${API_BASE}/api/chat/history?${params}`, {
    method: 'DELETE',
  });
}

// Fetch Detection Logs 
export async function fetchDetectionLogs(
  limit: number = 40,
  attackType?: string
): Promise<unknown[]> {
  const params = new URLSearchParams({ limit: String(limit) });
  if (attackType) params.append('attack_type', attackType);

  const response = await fetch(`${API_BASE}/api/logs?${params}`);
  const data = await handleResponse<unknown[]>(response);
  return data.data;
}

// Fetch Latest Detection
export async function fetchLatestDetection(): Promise<DetectionResult | null> {
  try {
    const logs = await fetchDetectionLogs(1);
    if (logs.length === 0) return null;
    return logs[0] as DetectionResult;
  } catch {
    return null;
  }
}