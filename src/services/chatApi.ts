import type { ChatRequest, ChatResponse, AIAnalysisResponse } from '@/types/chat';
import type { ApiResponse, AgentRequest, AgentResponse, ChatMessageRecord, ChatHistory } from '@/types/api';

const API_BASE = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

function buildErrorMessage(status: number, fallback: string): string {
  switch (status) {
    case 400:
      return 'The chat request was invalid.';
    case 404:
      return 'The chat endpoint was not found.';
    case 422:
      return 'The server rejected the chat payload.';
    case 500:
      return 'The chat service encountered an internal error.';
    case 502:
      return 'The AI gateway is currently unavailable.';
    default:
      return fallback;
  }
}

async function parseApiResponse<T>(response: Response, fallbackMessage: string): Promise<T> {
  const payload = (await response.json().catch(() => null)) as ApiResponse<T> | null;

  if (!response.ok) {
    const message = payload?.message || buildErrorMessage(response.status, fallbackMessage);
    throw new Error(message);
  }

  if (!payload?.success) {
    throw new Error(payload?.message || fallbackMessage);
  }

  return payload.data as T;
}

export async function sendChatMessage(request: ChatRequest): Promise<ChatResponse> {
  try {
    const body: AgentRequest = {
      messages: [{ role: 'user', content: request.message }],
      mode: 'chat',
      logs: [],
      user_id: 'local_user',
      session_id: request.session_id,
    };

    const response = await fetch(`${API_BASE}/api/agent`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    const payload = await parseApiResponse<AgentResponse>(response, 'Chat request failed');
    return {
      message: payload.message,
      type: 'analysis',
      suggestions: [],
      references: [],
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Chat request failed';
    throw new Error(message);
  }
}

export async function saveChatHistoryMessage(message: { user_id: string; role: 'user' | 'assistant' | 'system'; content: string; session_id?: string | null }): Promise<ChatMessageRecord> {
  const response = await fetch(`${API_BASE}/api/chat/message`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(message),
  });

  return parseApiResponse<ChatMessageRecord>(response, 'Unable to save chat message');
}

export async function getChatHistory(userId: string, sessionId?: string | null): Promise<ChatHistory> {
  const query = new URLSearchParams({ user_id: userId });
  if (sessionId) query.set('session_id', sessionId);

  const response = await fetch(`${API_BASE}/api/chat/history?${query.toString()}`);
  const messages = await parseApiResponse<ChatMessageRecord[]>(response, 'Unable to load chat history');
  return { messages, session_id: sessionId ?? null };
}

export async function clearChatHistory(userId: string, sessionId?: string | null): Promise<{ deleted: number }> {
  const query = new URLSearchParams({ user_id: userId });
  if (sessionId) query.set('session_id', sessionId);

  const response = await fetch(`${API_BASE}/api/chat/history?${query.toString()}`, { method: 'DELETE' });
  return parseApiResponse<{ deleted: number }>(response, 'Unable to clear chat history');
}

export async function getInitialAnalysis(
  attackType: string,
  confidence: number,
  severity: string,
  sessionId: string
): Promise<AIAnalysisResponse> {
  try {
    const payload = await sendChatMessage({
      message: `Analyze ${attackType} with ${confidence}% confidence and ${severity} severity for session ${sessionId}`,
      session_id: sessionId,
      context: {
        attack_type: attackType,
        confidence,
        severity,
        features: {},
        previous_messages: [],
      },
      type: 'initial_analysis',
    });

    return generateFallbackAnalysis(attackType, confidence, severity, payload.message);
  } catch {
    return generateFallbackAnalysis(attackType, confidence, severity);
  }
}

function generateFallbackAnalysis(
  attackType: string,
  confidence: number,
  severity: string,
  fallbackMessage?: string
): AIAnalysisResponse {
  const attackGuides: Record<string, Partial<AIAnalysisResponse>> = {
    SQL_Injection: {
      overview: 'SQL Injection is a code injection technique where malicious SQL statements are inserted into entry fields for execution. This attack can bypass authentication, extract sensitive data, modify database contents, or even delete entire databases.',
      attack_details: 'The attacker exploits improper input validation by injecting SQL code through user input fields. Common techniques include UNION-based attacks, error-based injection, blind SQL injection, and time-based attacks.',
      root_cause: 'Improper input validation and direct concatenation of user input into SQL queries without parameterization. Lack of prepared statements and insufficient input sanitization.',
      immediate_actions: [
        'Block the source IP address immediately',
        'Review database access logs for unauthorized queries',
        'Check for data exfiltration or unauthorized modifications',
        'Implement prepared statements for all database queries',
        'Enable database query logging and monitoring',
      ],
      prevention: [
        'Use parameterized queries (Prepared Statements) exclusively',
        'Implement strict input validation and sanitization',
        'Apply principle of least privilege for database accounts',
        'Use ORM frameworks that handle SQL escaping automatically',
        'Deploy Web Application Firewall (WAF) with SQLi rules',
        'Regular security testing with automated scanners',
      ],
      tools: ['Burp Suite', 'sqlmap', 'OWASP ZAP', 'ModSecurity WAF', 'Acunetix'],
      best_practices: [
        'Never trust user input - validate everything server-side',
        'Use stored procedures when possible',
        'Implement proper error handling without revealing database details',
        'Regular penetration testing and code reviews',
        'Keep all software and frameworks updated',
      ],
      references: [
        { title: 'OWASP SQL Injection', source: 'OWASP', url: 'https://owasp.org/www-community/attacks/SQL_Injection' },
        { title: 'MITRE ATT&CK: Exploit Public-Facing Application', source: 'MITRE', id: 'T1190' },
        { title: 'NIST: SQL Injection Prevention', source: 'NIST' },
      ],
      severity_assessment: 'Critical - SQL Injection is consistently ranked as the #1 web application security risk by OWASP.',
    },
    XSS: {
      overview: 'Cross-Site Scripting (XSS) attacks inject malicious scripts into web pages viewed by other users. These scripts can steal session cookies, redirect users to malicious sites, keylog user input, or perform actions on behalf of the victim.',
      attack_details: 'The attacker injects client-side scripts into web pages through user input fields, URL parameters, or stored data. When other users view the infected page, the malicious script executes in their browser.',
      root_cause: 'Web applications that include untrusted data in web pages without proper validation or escaping. Lack of output encoding and insufficient Content Security Policy.',
      immediate_actions: [
        'Identify and remove the injected script from all affected pages',
        'Invalidate all affected user sessions immediately',
        'Scan database for stored XSS payloads',
        'Enable Content Security Policy (CSP) headers',
        'Review access logs for exploitation attempts',
      ],
      prevention: [
        'Implement Content Security Policy (CSP) with strict directives',
        'Encode all output based on context (HTML, JavaScript, URL, CSS)',
        'Validate and sanitize all user inputs on server-side',
        'Use modern frameworks that auto-escape by default',
        'Implement HttpOnly and Secure flags on cookies',
        'Use X-XSS-Protection header',
      ],
      tools: ['Burp Suite', 'OWASP ZAP', 'DOMPurify', 'CSP Evaluator', 'Snyk'],
      best_practices: [
        'Use context-aware output encoding for all dynamic content',
        'Implement strict CSP policies with report-uri',
        'Avoid innerHTML and document.write in JavaScript',
        'Regular XSS vulnerability scanning and testing',
        'Security awareness training for developers',
      ],
      references: [
        { title: 'OWASP XSS Prevention Cheat Sheet', source: 'OWASP' },
        { title: 'MITRE ATT&CK: Drive-by Compromise', source: 'MITRE', id: 'T1189' },
        { title: 'NIST: XSS Guidance', source: 'NIST' },
      ],
      severity_assessment: 'High - XSS can lead to session hijacking, credential theft, and malware distribution.',
    },
  };

  const guide = attackGuides[attackType] || {};

  return {
    overview: guide.overview || `${attackType} attack detected with ${confidence}% confidence. This is a ${severity.toLowerCase()} severity threat that requires immediate attention.`,
    attack_details: guide.attack_details || `Detailed analysis of ${attackType} attack pattern.`,
    root_cause: guide.root_cause || 'Analysis of the root cause is pending detailed investigation.',
    immediate_actions: guide.immediate_actions || ['Investigate the alert immediately', 'Review affected systems', 'Apply security patches'],
    prevention: guide.prevention || ['Implement defense in depth strategy', 'Regular security updates', 'Monitor network traffic'],
    tools: guide.tools || ['Wireshark', 'Snort', 'Suricata'],
    best_practices: guide.best_practices || ['Stay vigilant', 'Keep systems updated', 'Monitor continuously'],
    references: guide.references || [
      { title: 'General Security Best Practices', source: 'NIST' },
    ],
    severity_assessment: guide.severity_assessment || `${severity} severity - Confidence: ${confidence}%`,
  };
}
