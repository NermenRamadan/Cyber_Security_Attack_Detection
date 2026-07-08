export interface PredictionFeatures {
  protocol: string;
  dest_port?: number | null;
  source_ip: string;
  source_port?: number | null;
  length?: number | null;
  ttl?: number | null;
  [key: string]: unknown;
}

export interface PredictionResult {
  is_attack: boolean;
  attack_type: string;
  severity: string;
  confidence?: number | null;
  binary_confidence?: number | null;
  code: number;
  solution: string;
  features: PredictionFeatures;
}

export interface ApiResponse<T> {
  success: boolean;
  message?: string | null;
  timestamp: string;
  data: T | null;
}

export interface ChatMessageRecord {
  id: string;
  user_id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  created_at: string;
  session_id?: string | null;
}

export interface ChatHistory {
  messages: ChatMessageRecord[];
  session_id?: string | null;
}

export interface DetectionLog {
  id: string;
  user_id?: string | null;
  detected_at: string;
  source_ip: string;
  status: string;
  attack_type: string;
  protocol: string;
  severity: string;
  confidence: number;
  solution?: string | null;
  device_id?: string | null;
  created_at: string;
}

export interface StatsOverview {
  total_detections: number;
  total_attacks: number;
  total_normal: number;
  severity_breakdown: Record<string, number>;
  attack_type_breakdown: Record<string, number>;
  last_detection_at?: string | null;
}

export interface TimelineData {
  date: string;
  count: number;
  attacks: number;
}

export type AttackType = string;

export interface AgentRequest {
  messages: Array<{ role: string; content: string }>;
  mode: 'chat' | 'summary';
  logs: Array<Record<string, unknown>>;
  user_id?: string;
  session_id?: string | null;
}

export interface AgentResponse {
  message: string;
  role: 'assistant';
  mode: 'chat' | 'summary';
  timestamp: string;
  session_id?: string | null;
}
