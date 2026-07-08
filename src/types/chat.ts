// Chat Types - AI Security Assistant

import type { MLPredictionResult, SHAPExplanation } from './detection';
import type { ChatMessageRecord, AgentResponse } from './api';

export type ChatMessage = {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  type: 'initial_analysis' | 'quick_reply' | 'freeform' | 'xai_explanation' | 'error' | 'loading';
  timestamp: Date;
  metadata?: MessageMetadata;
  suggestions?: QuickSuggestion[];
};

export interface MessageMetadata {
  attackType?: string;
  confidence?: number;
  severity?: string;
  references?: Reference[];
  shapExplanation?: SHAPExplanation;
  actionItems?: string[];
}

export interface QuickSuggestion {
  id: string;
  label: string;
  prompt: string;
  category: 'explanation' | 'mitigation' | 'technical' | 'tools' | 'learning';
  icon?: string;
}

export interface Reference {
  title: string;
  url?: string;
  source: 'OWASP' | 'MITRE' | 'NIST' | 'CVE' | 'Custom';
  id?: string;
}

export interface ChatSession {
  id: string;
  detectionResult: MLPredictionResult;
  messages: ChatMessage[];
  status: 'active' | 'ended';
  createdAt: Date;
  lastMessageAt: Date;
}

export interface AIAnalysisResponse {
  overview: string;
  attack_details: string;
  root_cause: string;
  immediate_actions: string[];
  prevention: string[];
  tools: string[];
  best_practices: string[];
  references: Reference[];
  severity_assessment: string;
}

export interface ChatRequest {
  message: string;
  session_id: string;
  context: {
    attack_type: string;
    confidence: number;
    severity: string;
    features: Record<string, unknown>;
    previous_messages: { role: string; content: string }[];
  };
  type: 'initial_analysis' | 'followup' | 'xai_request' | 'freeform';
}

export interface ChatResponse {
  message: string;
  type: 'analysis' | 'followup' | 'xai' | 'error';
  suggestions?: QuickSuggestion[];
  references?: Reference[];
  metadata?: {
    confidence?: number;
    action_items?: string[];
  };
}

export type ChatMessageRecordShape = ChatMessageRecord;
export type ChatAgentResponse = AgentResponse;

// ==========================================
// Context-Aware Quick Suggestions
// ==========================================

export function getInitialSuggestions(attackType: string): QuickSuggestion[] {
  return [
    {
      id: 'explain_more',
      label: 'Explain this attack in detail',
      prompt: `Provide a detailed technical explanation of ${attackType} attack. Include how it works, common techniques used, and why it's dangerous.`,
      category: 'explanation',
      icon: '📖',
    },
    {
      id: 'protect_network',
      label: 'How can I protect my network?',
      prompt: `What are the best security measures and configurations to prevent ${attackType} attacks on my network?`,
      category: 'mitigation',
      icon: '🛡️',
    },
    {
      id: 'mitigation_steps',
      label: 'Show mitigation steps',
      prompt: `List step-by-step mitigation actions for ${attackType} attack, ordered by priority and urgency.`,
      category: 'mitigation',
      icon: '⚡',
    },
    {
      id: 'why_classified',
      label: 'Why did the model classify it as this?',
      prompt: `Explain the machine learning classification for ${attackType}. What features and patterns led the XGBoost model to this prediction?`,
      category: 'technical',
      icon: '🧠',
    },
    {
      id: 'real_world',
      label: 'Show real-world examples',
      prompt: `Provide real-world case studies and notable incidents involving ${attackType} attacks.`,
      category: 'learning',
      icon: '🌍',
    },
    {
      id: 'linux_commands',
      label: 'Give me Linux commands',
      prompt: `What Linux commands and tools can I use to detect, analyze, and mitigate ${attackType} attacks?`,
      category: 'tools',
      icon: '🐧',
    },
    {
      id: 'confidence_explain',
      label: 'How confident is this prediction?',
      prompt: `Explain the confidence level of this ${attackType} prediction. What factors increase or decrease certainty?`,
      category: 'technical',
      icon: '📊',
    },
    {
      id: 'detection_tools',
      label: 'Show detection tools',
      prompt: `What security tools, IDS/IPS signatures, and monitoring rules can detect ${attackType} attacks?`,
      category: 'tools',
      icon: '🔧',
    },
  ];
}

// Follow-up suggestions based on conversation context
export function getFollowUpSuggestions(lastTopic: string): QuickSuggestion[] {
  const followUps: Record<string, QuickSuggestion[]> = {
    explanation: [
      { id: 'how_it_works', label: 'How does it work technically?', prompt: 'Explain the technical mechanism step by step.', category: 'technical', icon: '⚙️' },
      { id: 'variants', label: 'What are the variants?', prompt: 'List the different variants and sub-types of this attack.', category: 'learning', icon: '🔀' },
    ],
    mitigation: [
      { id: 'priority', label: 'What should I do first?', prompt: 'What is the highest priority action I should take right now?', category: 'mitigation', icon: '🚨' },
      { id: 'long_term', label: 'Long-term prevention?', prompt: 'What long-term security strategy should I implement?', category: 'mitigation', icon: '🏗️' },
    ],
    tools: [
      { id: 'install', label: 'How to install these tools?', prompt: 'Provide installation and configuration instructions.', category: 'tools', icon: '💿' },
      { id: 'compare', label: 'Compare these tools', prompt: 'Compare the pros and cons of each tool.', category: 'tools', icon: '⚖️' },
    ],
  };

  return followUps[lastTopic] || [];
}
