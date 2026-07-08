// Detection Types - ML Model Output

import type { PredictionResult, PredictionFeatures } from './api';

export type MLPredictionResult = PredictionResult & {
  timestamp?: string;
  risk_level?: string;
  destination_ip?: string;
};

export type ModelFeatures = PredictionFeatures;

// SHAP Explainable AI
export interface SHAPFeatureImportance {
  feature: string;
  value: number;
  impact: 'positive' | 'negative';
  description: string;
}

export interface SHAPExplanation {
  base_value: number;
  predicted_value: number;
  features: SHAPFeatureImportance[];
  top_positive: SHAPFeatureImportance[];
  top_negative: SHAPFeatureImportance[];
}

// Detection Session
export interface DetectionSession {
  id: string;
  status: 'idle' | 'uploading' | 'analyzing' | 'completed' | 'error';
  fileName?: string;
  results: MLPredictionResult[];
  summary: DetectionSummary;
  createdAt: Date;
  completedAt?: Date;
}

export interface DetectionSummary {
  total_packets: number;
  attacks_detected: number;
  attack_types: Record<string, number>;
  max_confidence: number;
  avg_confidence: number;
  highest_severity: string;
  top_source_ips: string[];
  time_range: { start: string; end: string };
}

// Attack Type Information (15 types from the model)
export const ATTACK_CATEGORIES = {
  flood: {
    label: 'Flood Attacks',
    icon: '🌊',
    color: 'text-blue-400',
    bgColor: 'bg-blue-500/10',
    attacks: ['DDoS_ICMP', 'DDoS_UDP', 'DDoS_RAW', 'DoS', 'SYN_Flood', 'ICMP_Flood'],
  },
  brute_force: {
    label: 'Brute Force',
    icon: '🔑',
    color: 'text-orange-400',
    bgColor: 'bg-orange-500/10',
    attacks: ['FTP_BruteForce', 'SSH_BruteForce', 'FTP_Exploit'],
  },
  web: {
    label: 'Web Attacks',
    icon: '🌐',
    color: 'text-purple-400',
    bgColor: 'bg-purple-500/10',
    attacks: ['SQL_Injection', 'XSS', 'RCE', 'Fuzzing'],
  },
  recon: {
    label: 'Reconnaissance',
    icon: '🔍',
    color: 'text-cyan-400',
    bgColor: 'bg-cyan-500/10',
    attacks: ['PortScanning', 'MITM_ARP'],
  },
  normal: {
    label: 'Normal Traffic',
    icon: '✅',
    color: 'text-green-400',
    bgColor: 'bg-green-500/10',
    attacks: ['Normal'],
  },
} as const;

export type AttackCategory = keyof typeof ATTACK_CATEGORIES;

export function getAttackCategory(attackType: string): AttackCategory {
  for (const [category, data] of Object.entries(ATTACK_CATEGORIES)) {
    if ((data.attacks as readonly string[]).includes(attackType)) {
      return category as AttackCategory;
    }
  }
  return 'normal';
}

export function getRiskConfig(confidence: number) {
  if (confidence >= 90) {
    return {
      level: 'Critical' as const,
      icon: '🔴',
      color: 'text-red-400',
      bgColor: 'bg-red-500/10',
      borderColor: 'border-red-500/30',
      progressColor: 'bg-red-500',
      description: 'Immediate action required!',
    };
  }
  if (confidence >= 70) {
    return {
      level: 'High' as const,
      icon: '🟠',
      color: 'text-orange-400',
      bgColor: 'bg-orange-500/10',
      borderColor: 'border-orange-500/30',
      progressColor: 'bg-orange-500',
      description: 'Urgent attention needed',
    };
  }
  if (confidence >= 50) {
    return {
      level: 'Medium' as const,
      icon: '🟡',
      color: 'text-yellow-400',
      bgColor: 'bg-yellow-500/10',
      borderColor: 'border-yellow-500/30',
      progressColor: 'bg-yellow-500',
      description: 'Should be addressed soon',
    };
  }
  return {
    level: 'Low' as const,
    icon: '🟢',
    color: 'text-green-400',
    bgColor: 'bg-green-500/10',
    borderColor: 'border-green-500/30',
    progressColor: 'bg-green-500',
    description: 'Minor concern, monitor',
  };
}

// Severity badge config
export function getSeverityConfig(severity: string) {
  switch (severity) {
    case 'Critical':
      return { color: 'bg-red-500/20 text-red-400 border-red-500/30', icon: '🔴' };
    case 'High':
      return { color: 'bg-orange-500/20 text-orange-400 border-orange-500/30', icon: '🟠' };
    case 'Medium':
      return { color: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30', icon: '🟡' };
    case 'Low':
      return { color: 'bg-green-500/20 text-green-400 border-green-500/30', icon: '🟢' };
    default:
      return { color: 'bg-slate-500/20 text-slate-400 border-slate-500/30', icon: '⚪' };
  }
}
