export const ATTACK_TYPES = [
  "DDoS",
  "SQL Injection",
  "XSS",
  "Brute Force",
  "Port Scan",
  "Phishing",
  "Malware",
  "Ransomware",
  "Man-in-the-Middle",
  "Zero-Day",
] as const;

export const PROTOCOLS = ["TCP", "UDP", "HTTP", "HTTPS", "DNS", "SSH", "ICMP"] as const;
export const SEVERITIES = ["Low", "Medium", "High", "Critical"] as const;

export interface Attack {
  id: string;
  detected_at: string;
  source_ip: string;
  source_country: string;
  status: "detected" | "monitored" | "flagged";
  attack_type: string;
  protocol: string;
  severity: string;
  confidence: number;
  solution: string;
}

export function severityColor(sev: string) {
  switch (sev) {
    case "Critical":
      return "text-destructive";
    case "High":
      return "text-warning";
    case "Medium":
      return "text-accent";
    default:
      return "text-muted-foreground";
  }
}

export function severityPillClass(sev: string) {
  switch (sev) {
    case "Critical":
      return "bg-destructive/15 text-destructive ring-1 ring-destructive/30";
    case "High":
      return "bg-warning/15 text-warning ring-1 ring-warning/30";
    case "Medium":
      return "bg-accent/15 text-accent ring-1 ring-accent/30";
    default:
      return "bg-success/15 text-success ring-1 ring-success/30";
  }
}
