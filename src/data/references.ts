// ═══════════════════════════════════════════════════════════════════════════════
// CYBERSHIELD AI — STATIC REFERENCE DATABASE
// ═══════════════════════════════════════════════════════════════════════════════
// This file maps attack types to official security references.
// Future: Replace with RAGReferenceProvider that queries a vector DB.
// ═══════════════════════════════════════════════════════════════════════════════

import type { Reference, ReferenceSource } from '@/types/agent';

// ── Source Metadata ────────────────────────────────────────────────────────────
export const SOURCE_META: Record<ReferenceSource, { icon: string; color: string; label: string }> = {
  OWASP:      { icon: '🛡️', color: '#58A6FF', label: 'OWASP' },
  MITRE:      { icon: '🎯', color: '#F85149', label: 'MITRE ATT&CK' },
  NIST:       { icon: '📋', color: '#3FB950', label: 'NIST' },
  CVE:        { icon: '🔓', color: '#F0883E', label: 'CVE' },
  Microsoft:  { icon: '🪟', color: '#58A6FF', label: 'Microsoft' },
  CISA:       { icon: '🏛️', color: '#A371F7', label: 'CISA' },
};

// ── Static Reference Database ──────────────────────────────────────────────────
export const STATIC_REFERENCES: Reference[] = [
  // ═══════════════════════════════════════════════════════════════════════════════
  // DDoS / Flood Attacks
  // ═══════════════════════════════════════════════════════════════════════════════
  {
    id: 'owasp-ddos',
    name: 'OWASP — Denial of Service',
    description: 'Comprehensive guide on DoS attack types, impact, and mitigation strategies for web applications.',
    url: 'https://owasp.org/www-community/attacks/Denial_of_Service',
    source: 'OWASP',
    icon: '🛡️',
    badgeColor: '#58A6FF',
    attackTypes: ['DDoS_ICMP', 'DDoS_UDP', 'DDoS_RAW', 'DoS', 'SYN_Flood', 'ICMP_Flood'],
  },
  {
    id: 'mitre-t1498',
    name: 'MITRE ATT&CK — T1498: Network Denial of Service',
    description: 'Adversary technique for flooding network resources to degrade or deny availability.',
    url: 'https://attack.mitre.org/techniques/T1498/',
    source: 'MITRE',
    icon: '🎯',
    badgeColor: '#F85149',
    attackTypes: ['DDoS_ICMP', 'DDoS_UDP', 'DDoS_RAW', 'DoS', 'SYN_Flood', 'ICMP_Flood'],
  },
  {
    id: 'nist-sp800-61',
    name: 'NIST SP 800-61 Rev. 2 — Computer Security Incident Handling',
    description: 'Guidelines for incident handling, including DDoS response procedures and containment strategies.',
    url: 'https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf',
    source: 'NIST',
    icon: '📋',
    badgeColor: '#3FB950',
    attackTypes: ['DDoS_ICMP', 'DDoS_UDP', 'DDoS_RAW', 'DoS', 'SYN_Flood', 'ICMP_Flood'],
  },
  {
    id: 'ms-ddos-protection',
    name: 'Microsoft — Azure DDoS Protection',
    description: 'Microsoft\'s cloud-native DDoS protection service with automatic attack mitigation.',
    url: 'https://docs.microsoft.com/en-us/azure/ddos-protection/ddos-protection-overview',
    source: 'Microsoft',
    icon: '🪟',
    badgeColor: '#58A6FF',
    attackTypes: ['DDoS_ICMP', 'DDoS_UDP', 'DDoS_RAW', 'DoS', 'SYN_Flood', 'ICMP_Flood'],
  },
  {
    id: 'cisa-ddos',
    name: 'CISA — Understanding and Responding to DDoS Attacks',
    description: 'Federal guidance on DDoS attack identification, impact assessment, and response coordination.',
    url: 'https://www.cisa.gov/news-events/news/understanding-denial-service-attacks',
    source: 'CISA',
    icon: '🏛️',
    badgeColor: '#A371F7',
    attackTypes: ['DDoS_ICMP', 'DDoS_UDP', 'DDoS_RAW', 'DoS', 'SYN_Flood', 'ICMP_Flood'],
  },

  // ═══════════════════════════════════════════════════════════════════════════════
  // Brute Force
  // ═══════════════════════════════════════════════════════════════════════════════
  {
    id: 'owasp-brute',
    name: 'OWASP — Brute Force Attack',
    description: 'Explains credential stuffing, password spraying, and account lockout mechanisms.',
    url: 'https://owasp.org/www-community/attacks/Brute_force_attack',
    source: 'OWASP',
    icon: '🛡️',
    badgeColor: '#58A6FF',
    attackTypes: ['SSH_BruteForce', 'FTP_BruteForce', 'FTP_Exploit'],
  },
  {
    id: 'mitre-t1110',
    name: 'MITRE ATT&CK — T1110: Brute Force',
    description: 'Techniques for guessing credentials through password cracking and spraying attacks.',
    url: 'https://attack.mitre.org/techniques/T1110/',
    source: 'MITRE',
    icon: '🎯',
    badgeColor: '#F85149',
    attackTypes: ['SSH_BruteForce', 'FTP_BruteForce', 'FTP_Exploit'],
  },
  {
    id: 'nist-sp800-63',
    name: 'NIST SP 800-63B — Digital Identity Guidelines',
    description: 'Authentication and lifecycle management, including memorized secret verifiers.',
    url: 'https://pages.nist.gov/800-63-3/sp800-63b.html',
    source: 'NIST',
    icon: '📋',
    badgeColor: '#3FB950',
    attackTypes: ['SSH_BruteForce', 'FTP_BruteForce', 'FTP_Exploit'],
  },
  {
    id: 'ms-password-guidance',
    name: 'Microsoft — Password Guidance',
    description: 'Best practices for password policies, MFA implementation, and account protection.',
    url: 'https://docs.microsoft.com/en-us/microsoft-365/admin/misc/password-policy-recommendations',
    source: 'Microsoft',
    icon: '🪟',
    badgeColor: '#58A6FF',
    attackTypes: ['SSH_BruteForce', 'FTP_BruteForce', 'FTP_Exploit'],
  },

  // ═══════════════════════════════════════════════════════════════════════════════
  // SQL Injection
  // ═══════════════════════════════════════════════════════════════════════════════
  {
    id: 'owasp-sqli',
    name: 'OWASP — SQL Injection (SQLi)',
    description: 'Top 10 vulnerability. Explains injection flaws, blind SQLi, and parameterized queries.',
    url: 'https://owasp.org/www-community/attacks/SQL_Injection',
    source: 'OWASP',
    icon: '🛡️',
    badgeColor: '#58A6FF',
    attackTypes: ['SQL_Injection'],
  },
  {
    id: 'mitre-t1190',
    name: 'MITRE ATT&CK — T1190: Exploit Public-Facing Application',
    description: 'Exploitation of web applications to gain initial access, including SQL injection.',
    url: 'https://attack.mitre.org/techniques/T1190/',
    source: 'MITRE',
    icon: '🎯',
    badgeColor: '#F85149',
    attackTypes: ['SQL_Injection', 'XSS', 'RCE', 'Fuzzing'],
  },
  {
    id: 'cve-sqli-examples',
    name: 'CVE — Notable SQL Injection Vulnerabilities',
    description: 'Historical CVEs demonstrating SQLi impact: CVE-2017-9805 (Apache Struts), CVE-2019-19781 (Citrix).',
    url: 'https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=sql+injection',
    source: 'CVE',
    icon: '🔓',
    badgeColor: '#F0883E',
    attackTypes: ['SQL_Injection'],
  },
  {
    id: 'nist-db-security',
    name: 'NIST — Database Security Guidelines',
    description: 'Comprehensive database security controls including input validation and query parameterization.',
    url: 'https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-73-4.pdf',
    source: 'NIST',
    icon: '📋',
    badgeColor: '#3FB950',
    attackTypes: ['SQL_Injection'],
  },

  // ═══════════════════════════════════════════════════════════════════════════════
  // XSS (Cross-Site Scripting)
  // ═══════════════════════════════════════════════════════════════════════════════
  {
    id: 'owasp-xss',
    name: 'OWASP — Cross-Site Scripting (XSS)',
    description: 'Stored, reflected, and DOM-based XSS. CSP headers and output encoding guidance.',
    url: 'https://owasp.org/www-community/attacks/xss/',
    source: 'OWASP',
    icon: '🛡️',
    badgeColor: '#58A6FF',
    attackTypes: ['XSS'],
  },
  {
    id: 'mitre-t1189',
    name: 'MITRE ATT&CK — T1189: Drive-by Compromise',
    description: 'Malicious websites compromising visitors through XSS and other web-based attacks.',
    url: 'https://attack.mitre.org/techniques/T1189/',
    source: 'MITRE',
    icon: '🎯',
    badgeColor: '#F85149',
    attackTypes: ['XSS', 'RCE'],
  },
  {
    id: 'cve-xss-examples',
    name: 'CVE — XSS Vulnerability Database',
    description: 'Curated list of high-impact XSS vulnerabilities in popular web frameworks.',
    url: 'https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=cross+site+scripting',
    source: 'CVE',
    icon: '🔓',
    badgeColor: '#F0883E',
    attackTypes: ['XSS'],
  },

  // ═══════════════════════════════════════════════════════════════════════════════
  // RCE (Remote Code Execution)
  // ═══════════════════════════════════════════════════════════════════════════════
  {
    id: 'owasp-rce',
    name: 'OWASP — Remote Code Execution',
    description: 'Injection flaws leading to arbitrary code execution on the server.',
    url: 'https://owasp.org/www-community/vulnerabilities/Command_Injection',
    source: 'OWASP',
    icon: '🛡️',
    badgeColor: '#58A6FF',
    attackTypes: ['RCE'],
  },
  {
    id: 'mitre-t1059',
    name: 'MITRE ATT&CK — T1059: Command and Scripting Interpreter',
    description: 'Abuse of command interpreters to execute arbitrary commands on compromised systems.',
    url: 'https://attack.mitre.org/techniques/T1059/',
    source: 'MITRE',
    icon: '🎯',
    badgeColor: '#F85149',
    attackTypes: ['RCE'],
  },
  {
    id: 'cisa-rce-alert',
    name: 'CISA — RCE Vulnerability Alert',
    description: 'Critical alerts and advisories for actively exploited RCE vulnerabilities.',
    url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
    source: 'CISA',
    icon: '🏛️',
    badgeColor: '#A371F7',
    attackTypes: ['RCE'],
  },

  // ═══════════════════════════════════════════════════════════════════════════════
  // Port Scanning / Reconnaissance
  // ═══════════════════════════════════════════════════════════════════════════════
  {
    id: 'owasp-recon',
    name: 'OWASP — Information Gathering',
    description: 'Reconnaissance techniques and defensive countermeasures for network mapping.',
    url: 'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/README',
    source: 'OWASP',
    icon: '🛡️',
    badgeColor: '#58A6FF',
    attackTypes: ['PortScanning'],
  },
  {
    id: 'mitre-t1046',
    name: 'MITRE ATT&CK — T1046: Network Service Scanning',
    description: 'Adversary scanning for open ports and vulnerable services across the network.',
    url: 'https://attack.mitre.org/techniques/T1046/',
    source: 'MITRE',
    icon: '🎯',
    badgeColor: '#F85149',
    attackTypes: ['PortScanning'],
  },
  {
    id: 'nist-network-monitoring',
    name: 'NIST — Network Security Monitoring',
    description: 'Guidelines for detecting and responding to reconnaissance activities.',
    url: 'https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-137.pdf',
    source: 'NIST',
    icon: '📋',
    badgeColor: '#3FB950',
    attackTypes: ['PortScanning'],
  },

  // ═══════════════════════════════════════════════════════════════════════════════
  // Fuzzing
  // ═══════════════════════════════════════════════════════════════════════════════
  {
    id: 'owasp-fuzzing',
    name: 'OWASP — Fuzzing',
    description: 'Input fuzzing techniques for vulnerability discovery and application security testing.',
    url: 'https://owasp.org/www-community/Fuzzing',
    source: 'OWASP',
    icon: '🛡️',
    badgeColor: '#58A6FF',
    attackTypes: ['Fuzzing'],
  },
  {
    id: 'mitre-t1071',
    name: 'MITRE ATT&CK — T1071: Application Layer Protocol',
    description: 'Abuse of application layer protocols for command and control, often preceded by fuzzing.',
    url: 'https://attack.mitre.org/techniques/T1071/',
    source: 'MITRE',
    icon: '🎯',
    badgeColor: '#F85149',
    attackTypes: ['Fuzzing', 'RCE'],
  },

  // ═══════════════════════════════════════════════════════════════════════════════
  // Normal Traffic (False Positive Guidance)
  // ═══════════════════════════════════════════════════════════════════════════════
  {
    id: 'nist-false-positives',
    name: 'NIST — False Positive Reduction',
    description: 'Strategies for reducing false positives in intrusion detection and security monitoring.',
    url: 'https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-94.pdf',
    source: 'NIST',
    icon: '📋',
    badgeColor: '#3FB950',
    attackTypes: ['Normal'],
  },
  {
    id: 'owasp-fp',
    name: 'OWASP — False Positives in Security Testing',
    description: 'Understanding and managing false positives in automated security scanning tools.',
    url: 'https://owasp.org/www-project-web-security-testing-guide/latest/',
    source: 'OWASP',
    icon: '🛡️',
    badgeColor: '#58A6FF',
    attackTypes: ['Normal'],
  },
];

// ── Helper: Get references by attack type ──────────────────────────────────────
export function getReferencesByAttackType(attackType: string): Reference[] {
  return STATIC_REFERENCES.filter(
    (ref) => ref.attackTypes.includes(attackType) || ref.attackTypes.includes('All')
  );
}

// ── Helper: Get all unique sources ──────────────────────────────────────────────
export function getAllSources(): ReferenceSource[] {
  return Array.from(new Set(STATIC_REFERENCES.map((r) => r.source)));
}

// ── Helper: Get references filtered by source ───────────────────────────────────
export function getReferencesBySource(attackType: string, source: ReferenceSource): Reference[] {
  return getReferencesByAttackType(attackType).filter((ref) => ref.source === source);
}