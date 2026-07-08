// Attack Types - matching the 15 types from the ML model
export interface AttackTypeInfo {
  id: string;
  label: string;
  category: 'flood' | 'brute_force' | 'web' | 'recon' | 'normal';
  icon: string;
  description: string;
}

// Risk Level Type
export type RiskLevel = 'Critical' | 'High' | 'Medium' | 'Low';

// Message Type
export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  attackType?: string;
  confidence?: number;
  riskLevel?: RiskLevel;
  timestamp: Date;
  isLoading?: boolean;
  responseData?: AttackResponse;
}

// n8n Webhook Request
export interface WebhookRequest {
  attack_type: string;
  confidence: number;
  features: {
    deltatime_new: number;
    protocol: string;
    tcp_flags: string;
    dest_port: number;
    length: number;
    is_attack_tool: string;
    is_http_request: boolean;
    is_http_error: boolean;
    ip_ttl: number;
  };
}

// Gemini Response from n8n
export interface AttackResponse {
  overview: string;
  severity: string;
  risk_level: string;
  immediate_actions: string[];
  root_cause: string;
  prevention: string[];
  tools: string[];
  best_practices: string[];
  mitre_attack?: string[];
  owasp_reference?: string[];
  nist_reference?: string[];
}

// Attack Types Data
export const ATTACK_TYPES: AttackTypeInfo[] = [
  // Normal
  { id: 'Normal', label: 'Normal Traffic', category: 'normal', icon: '✅', description: 'Regular network traffic, no threat detected' },
  // Flood Attacks
  { id: 'DDoS_ICMP', label: 'DDoS ICMP', category: 'flood', icon: '🌊', description: 'Distributed Denial of Service via ICMP flood' },
  { id: 'DDoS_UDP', label: 'DDoS UDP', category: 'flood', icon: '🌊', description: 'Distributed Denial of Service via UDP flood' },
  { id: 'DDoS_RAW', label: 'DDoS RAW', category: 'flood', icon: '🌊', description: 'Raw socket-based DDoS attack' },
  { id: 'DoS', label: 'DoS Attack', category: 'flood', icon: '🌊', description: 'Denial of Service attack' },
  { id: 'SYN_Flood', label: 'SYN Flood', category: 'flood', icon: '🌊', description: 'TCP SYN flood attack' },
  { id: 'ICMP_Flood', label: 'ICMP Flood', category: 'flood', icon: '🌊', description: 'ICMP ping flood attack' },
  // Brute Force
  { id: 'FTP_BruteForce', label: 'FTP Brute Force', category: 'brute_force', icon: '🔑', description: 'FTP password brute force attempt' },
  { id: 'SSH_BruteForce', label: 'SSH Brute Force', category: 'brute_force', icon: '🔑', description: 'SSH password brute force attempt' },
  { id: 'FTP_Exploit', label: 'FTP Exploit', category: 'brute_force', icon: '🔑', description: 'FTP service exploitation' },
  // Web Attacks
  { id: 'SQL_Injection', label: 'SQL Injection', category: 'web', icon: '🌐', description: 'SQL injection attack on web application' },
  { id: 'XSS', label: 'Cross-Site Scripting', category: 'web', icon: '🌐', description: 'XSS attack on web application' },
  { id: 'RCE', label: 'Remote Code Execution', category: 'web', icon: '🌐', description: 'Remote code execution vulnerability' },
  { id: 'Fuzzing', label: 'Fuzzing Attack', category: 'web', icon: '🌐', description: 'Input fuzzing attack' },
  // Reconnaissance
  { id: 'PortScanning', label: 'Port Scanning', category: 'recon', icon: '🔍', description: 'Network port scanning activity' },
  { id: 'MITM_ARP', label: 'MITM ARP', category: 'recon', icon: '🔍', description: 'Man-in-the-middle ARP spoofing' },
];

// Risk Level Configuration
export const RISK_CONFIG: Record<RiskLevel, { color: string; bgColor: string; borderColor: string; icon: string; description: string }> = {
  Critical: {
    color: 'text-red-400',
    bgColor: 'bg-red-500/10',
    borderColor: 'border-red-500/30',
    icon: '🔴',
    description: 'Immediate action required!'
  },
  High: {
    color: 'text-orange-400',
    bgColor: 'bg-orange-500/10',
    borderColor: 'border-orange-500/30',
    icon: '🟠',
    description: 'Urgent attention needed'
  },
  Medium: {
    color: 'text-yellow-400',
    bgColor: 'bg-yellow-500/10',
    borderColor: 'border-yellow-500/30',
    icon: '🟡',
    description: 'Should be addressed soon'
  },
  Low: {
    color: 'text-green-400',
    bgColor: 'bg-green-500/10',
    borderColor: 'border-green-500/30',
    icon: '🟢',
    description: 'Minor concern, monitor'
  }
};

// Helper function to get risk level from confidence
export function getRiskLevel(confidence: number): RiskLevel {
  if (confidence >= 90) return 'Critical';
  if (confidence >= 70) return 'High';
  if (confidence >= 50) return 'Medium';
  return 'Low';
}
