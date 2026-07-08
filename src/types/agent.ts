// CYBERSHIELD AI — AGENT TYPES

import type { DetectionResult } from './detection';

// Risk Level
export type RiskLevel = 'Critical' | 'High' | 'Medium' | 'Low' | 'None';

// Chat
export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp: string;
  attackType?: string;
  confidence?: number;
  riskLevel?: RiskLevel;
  isLoading?: boolean;
}

// Detection Result (matches backend PredictionResult)
export interface DetectionFeatures {
  protocol: string;
  dest_port?: number;
  source_ip: string;
  source_port?: number;
  length?: number;
  ttl?: number;
}

export interface DetectionResult {
  is_attack: boolean;
  attack_type: string;
  severity: string;
  confidence: number | null;
  binary_confidence: number | null;
  code: number;
  solution: string;
  features: DetectionFeatures;
}

// Initial Analysis 
export interface AnalysisData {
  overview: string;
  rootCause: string;
  immediateActions: string[];
  prevention: string[];
  tools: string[];
  bestPractices: string[];
  mitreTechniques?: string[];
  owaspCategory?: string;
}

// Suggestions 
export interface Suggestion {
  id: string;
  label: string;
  prompt: string;
  category: 'explain' | 'mitigate' | 'prevent' | 'tools' | 'checklist';
  icon: string;
}

// Session 
export interface AgentSession {
  sessionId: string;
  detectionId: string;
  attackType: string;
  severity: string;
  confidence: number;
  sourceIp: string;
  protocol: string;
  timestamp: string;
  messages: ChatMessage[];
  analysis: AnalysisData | null;
  isAnalysisLoading: boolean;
  isChatLoading: boolean;
}

// Reference System (Future RAG Ready) 
export type ReferenceSource = 'OWASP' | 'MITRE' | 'NIST' | 'CVE' | 'Microsoft' | 'CISA';

export interface Reference {
  id: string;
  name: string;
  description: string;
  url: string;
  source: ReferenceSource;
  icon: string;
  badgeColor: string;
  relevanceScore?: number; // For future RAG
  attackTypes: string[];   // Which attacks this reference applies to
}

// Reference Provider Interface (Strategy Pattern) 
export interface ReferenceProvider {
  readonly name: string;
  readonly isRag: boolean;
  getReferences(attackType: string): Promise<Reference[]> | Reference[];
  search?(query: string, attackType: string): Promise<Reference[]>;
}

// API Response Types 
export interface ApiResponse<T = unknown> {
  success: boolean;
  data: T;
  message: string;
  timestamp: string;
}

export interface AgentApiResponse {
  message: string;
  role: string;
  mode: string;
  timestamp: string;
  session_id?: string;
}

export interface ChatHistoryResponse {
  id: string;
  user_id: string;
  role: string;
  content: string;
  created_at: string;
  session_id?: string;
}