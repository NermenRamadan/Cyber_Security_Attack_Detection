// ═══════════════════════════════════════════════════════════════════════════════
// CYBERSHIELD AI — DYNAMIC ATTACK SUGGESTIONS
// ═══════════════════════════════════════════════════════════════════════════════
// Generates contextual questions based on the detected attack type.
// Each attack category has tailored suggestions for deeper investigation.
// ═══════════════════════════════════════════════════════════════════════════════

import { motion } from 'framer-motion';
import {
  HelpCircle,
  Shield,
  Lock,
  Search,
  FileCheck,
  Wrench,
  BookOpen,
  AlertTriangle,
  Network,
  Code,
  Eye,
  Terminal,
} from 'lucide-react';
import type { Suggestion } from '@/types/agent';

interface AttackSuggestionsProps {
  attackType: string;
  onSuggestionClick: (prompt: string) => void;
  className?: string;
}

// ── Suggestion Database by Attack Category ────────────────────────────────────
const SUGGESTION_DB: Record<string, Suggestion[]> = {
  // Flood / DDoS Attacks
  'DDoS_ICMP': [
    { id: 'ddos-1', label: 'How does ICMP flood work?', prompt: 'Explain how ICMP flood attacks work at the network level and why they are effective.', category: 'explain', icon: 'HelpCircle' },
    { id: 'ddos-2', label: 'Rate limiting rules', prompt: 'Show me specific iptables/pfSense rules to rate limit ICMP traffic effectively.', category: 'mitigate', icon: 'Shield' },
    { id: 'ddos-3', label: 'Identify the source', prompt: 'How can I trace the true source of a DDoS attack through multiple layers of reflection?', category: 'tools', icon: 'Search' },
    { id: 'ddos-4', label: 'DDoS mitigation checklist', prompt: 'Give me a complete incident response checklist for handling an active DDoS attack.', category: 'checklist', icon: 'FileCheck' },
    { id: 'ddos-5', label: 'Cloudflare vs AWS Shield', prompt: 'Compare Cloudflare Magic Transit vs AWS Shield Advanced for DDoS protection.', category: 'prevent', icon: 'Network' },
  ],
  'DDoS_UDP': [
    { id: 'udp-1', label: 'UDP amplification explained', prompt: 'Explain UDP amplification attacks and list common protocols used (DNS, NTP, SSDP).', category: 'explain', icon: 'HelpCircle' },
    { id: 'udp-2', label: 'Block UDP flood', prompt: 'Show me firewall rules to block UDP flood attacks while preserving legitimate DNS traffic.', category: 'mitigate', icon: 'Shield' },
    { id: 'udp-3', label: 'ISP coordination', prompt: 'What information should I provide to my ISP when requesting DDoS mitigation assistance?', category: 'tools', icon: 'Network' },
    { id: 'udp-4', label: 'Monitoring setup', prompt: 'How do I set up real-time alerting for UDP flood attacks using Prometheus and Grafana?', category: 'prevent', icon: 'Eye' },
  ],
  'SYN_Flood': [
    { id: 'syn-1', label: 'SYN cookies explained', prompt: 'Explain how SYN cookies work to prevent SYN flood attacks without allocating resources.', category: 'explain', icon: 'HelpCircle' },
    { id: 'syn-2', label: 'Enable SYN cookies', prompt: 'Show me how to enable and configure SYN cookies on Linux, FreeBSD, and Windows Server.', category: 'mitigate', icon: 'Shield' },
    { id: 'syn-3', label: 'Connection backlog tuning', prompt: 'How do I tune TCP connection backlog and timeouts to resist SYN flood attacks?', category: 'prevent', icon: 'Wrench' },
  ],

  // Brute Force
  'SSH_BruteForce': [
    { id: 'ssh-1', label: 'Why target SSH?', prompt: 'Why do attackers target SSH specifically, and what makes it attractive for brute force?', category: 'explain', icon: 'HelpCircle' },
    { id: 'ssh-2', label: 'Fail2Ban config', prompt: 'Show me a complete fail2ban configuration for SSH with progressive ban times.', category: 'mitigate', icon: 'Shield' },
    { id: 'ssh-3', label: 'Key-based auth only', prompt: 'How do I completely disable password authentication and enforce key-based SSH access?', category: 'prevent', icon: 'Lock' },
    { id: 'ssh-4', label: 'Port knocking', prompt: 'Explain port knocking and single-packet authorization as alternatives to changing SSH ports.', category: 'prevent', icon: 'Network' },
    { id: 'ssh-5', label: 'HoneyPot setup', prompt: 'How do I set up an SSH honeypot to detect and analyze brute force attempts?', category: 'tools', icon: 'Eye' },
  ],
  'FTP_BruteForce': [
    { id: 'ftp-1', label: 'FTP vulnerabilities', prompt: 'Why is FTP insecure for authentication, and what alternatives should I use (SFTP/FTPS)?', category: 'explain', icon: 'HelpCircle' },
    { id: 'ftp-2', label: 'Disable FTP', prompt: 'Show me how to safely migrate from FTP to SFTP and disable the FTP service.', category: 'mitigate', icon: 'Shield' },
    { id: 'ftp-3', label: 'Account lockout', prompt: 'How do I implement account lockout policies for FTP brute force attempts?', category: 'prevent', icon: 'Lock' },
  ],

  // Web Attacks
  'SQL_Injection': [
    { id: 'sqli-1', label: 'How SQLi works', prompt: 'Explain SQL injection with concrete examples: union-based, blind, and time-based attacks.', category: 'explain', icon: 'HelpCircle' },
    { id: 'sqli-2', label: 'Parameterized queries', prompt: 'Show me code examples of parameterized queries in Python, Node.js, Java, and PHP.', category: 'mitigate', icon: 'Code' },
    { id: 'sqli-3', label: 'WAF rules', prompt: 'What ModSecurity/OWASP CRS rules should I enable to detect and block SQL injection?', category: 'prevent', icon: 'Shield' },
    { id: 'sqli-4', label: 'Testing tools', prompt: 'List and compare SQLMap, Burp Suite, and other tools for testing SQL injection vulnerabilities.', category: 'tools', icon: 'Terminal' },
    { id: 'sqli-5', label: 'Secure ORM patterns', prompt: 'What ORM patterns prevent SQL injection, and what anti-patterns should I avoid?', category: 'prevent', icon: 'BookOpen' },
  ],
  'XSS': [
    { id: 'xss-1', label: 'XSS types explained', prompt: 'Explain stored, reflected, and DOM-based XSS with real-world examples for each.', category: 'explain', icon: 'HelpCircle' },
    { id: 'xss-2', label: 'CSP headers', prompt: 'Show me a complete Content Security Policy header configuration to mitigate XSS.', category: 'mitigate', icon: 'Shield' },
    { id: 'xss-3', label: 'Output encoding', prompt: 'How do I properly encode output for HTML, JavaScript, CSS, and URL contexts?', category: 'prevent', icon: 'Code' },
    { id: 'xss-4', label: 'XSS testing', prompt: 'What tools and payloads should I use to test for XSS vulnerabilities in my application?', category: 'tools', icon: 'Terminal' },
  ],
  'RCE': [
    { id: 'rce-1', label: 'RCE attack vectors', prompt: 'What are the most common vectors for remote code execution in web applications?', category: 'explain', icon: 'HelpCircle' },
    { id: 'rce-2', label: 'Patch management', prompt: 'How do I implement an effective patch management process for critical RCE vulnerabilities?', category: 'mitigate', icon: 'Shield' },
    { id: 'rce-3', label: 'Sandboxing', prompt: 'What sandboxing and containerization strategies prevent RCE from compromising the host?', category: 'prevent', icon: 'Lock' },
  ],

  // Reconnaissance
  'PortScanning': [
    { id: 'port-1', label: 'Scan types', prompt: 'Explain the difference between SYN, Connect, UDP, and FIN port scans.', category: 'explain', icon: 'HelpCircle' },
    { id: 'port-2', label: 'Detect scans', prompt: 'How do I detect port scanning attempts using IDS/IPS and network monitoring?', category: 'mitigate', icon: 'Eye' },
    { id: 'port-3', label: 'Port knocking', prompt: 'Implement port knocking or single-packet authorization to hide services from scanners.', category: 'prevent', icon: 'Network' },
    { id: 'port-4', label: 'Decoy ports', prompt: 'How do I set up honeypot ports to detect and analyze reconnaissance activity?', category: 'tools', icon: 'AlertTriangle' },
  ],

  // Normal / False Positive
  'Normal': [
    { id: 'norm-1', label: 'Why flagged?', prompt: 'Why was this traffic flagged by the ML model, and what features triggered the detection?', category: 'explain', icon: 'HelpCircle' },
    { id: 'norm-2', label: 'Reduce false positives', prompt: 'How do I tune the detection model to reduce false positives for this traffic pattern?', category: 'prevent', icon: 'Wrench' },
    { id: 'norm-3', label: 'Confidence explained', prompt: 'Explain what the confidence score means and how to interpret model predictions.', category: 'explain', icon: 'BookOpen' },
  ],

  // Default / Generic
  'default': [
    { id: 'def-1', label: 'Explain this attack', prompt: 'Explain this attack type in simple terms, how it works, and what makes it dangerous.', category: 'explain', icon: 'HelpCircle' },
    { id: 'def-2', label: 'How to prevent it', prompt: 'What are the most effective prevention strategies and security controls for this attack?', category: 'prevent', icon: 'Shield' },
    { id: 'def-3', label: 'Mitigation steps', prompt: 'Give me step-by-step mitigation actions I can take right now to stop this attack.', category: 'mitigate', icon: 'Wrench' },
    { id: 'def-4', label: 'Detection tools', prompt: 'What security tools and technologies are best for detecting this type of attack?', category: 'tools', icon: 'Search' },
    { id: 'def-5', label: 'Incident response', prompt: 'Provide a complete incident response checklist specific to this attack type.', category: 'checklist', icon: 'FileCheck' },
  ],
};

// ── Icon Mapping ──────────────────────────────────────────────────────────────
const iconComponents: Record<string, React.ReactNode> = {
  HelpCircle: <HelpCircle className="h-3.5 w-3.5" />,
  Shield: <Shield className="h-3.5 w-3.5" />,
  Lock: <Lock className="h-3.5 w-3.5" />,
  Search: <Search className="h-3.5 w-3.5" />,
  FileCheck: <FileCheck className="h-3.5 w-3.5" />,
  Wrench: <Wrench className="h-3.5 w-3.5" />,
  BookOpen: <BookOpen className="h-3.5 w-3.5" />,
  AlertTriangle: <AlertTriangle className="h-3.5 w-3.5" />,
  Network: <Network className="h-3.5 w-3.5" />,
  Code: <Code className="h-3.5 w-3.5" />,
  Eye: <Eye className="h-3.5 w-3.5" />,
  Terminal: <Terminal className="h-3.5 w-3.5" />,
};

// ── Category Colors ─────────────────────────────────────────────────────────────
const categoryColors: Record<string, string> = {
  explain: 'bg-blue-500/10 text-blue-400 border-blue-500/20 hover:bg-blue-500/20',
  mitigate: 'bg-orange-500/10 text-orange-400 border-orange-500/20 hover:bg-orange-500/20',
  prevent: 'bg-green-500/10 text-green-400 border-green-500/20 hover:bg-green-500/20',
  tools: 'bg-purple-500/10 text-purple-400 border-purple-500/20 hover:bg-purple-500/20',
  checklist: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20 hover:bg-yellow-500/20',
};

// ── Main Component ─────────────────────────────────────────────────────────────
export function AttackSuggestions({ attackType, onSuggestionClick, className = '' }: AttackSuggestionsProps) {
  const suggestions = SUGGESTION_DB[attackType] || SUGGESTION_DB['default'];

  return (
    <div className={className}>
      <div className="flex items-center gap-2 mb-3">
        <HelpCircle className="h-4 w-4 text-primary" />
        <h3 className="text-sm font-semibold text-foreground">Suggested Questions</h3>
        <span className="text-xs text-muted-foreground">({suggestions.length})</span>
      </div>

      <div className="flex flex-wrap gap-2">
        {suggestions.map((suggestion, index) => (
          <motion.button
            key={suggestion.id}
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.2, delay: index * 0.05 }}
            whileHover={{ scale: 1.03 }}
            whileTap={{ scale: 0.97 }}
            onClick={() => onSuggestionClick(suggestion.prompt)}
            className={`inline-flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-medium border transition-all duration-200 ${
              categoryColors[suggestion.category] || categoryColors['explain']
            }`}
            title={suggestion.prompt}
          >
            {iconComponents[suggestion.icon] || <HelpCircle className="h-3.5 w-3.5" />}
            <span>{suggestion.label}</span>
          </motion.button>
        ))}
      </div>
    </div>
  );
}