import type { MLPredictionResult, SHAPExplanation } from '@/types/detection';
import type { ApiResponse, PredictionResult, DetectionLog, StatsOverview, TimelineData } from '@/types/api';

const API_BASE = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

function buildErrorMessage(status: number, fallback: string): string {
  switch (status) {
    case 400:
      return 'The request payload was invalid.';
    case 404:
      return 'The requested prediction endpoint was not found.';
    case 422:
      return 'The server rejected the payload shape.';
    case 500:
      return 'The server encountered an internal error.';
    case 502:
      return 'The upstream AI service is unavailable.';
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

  return (payload.data as T) as T;
}

export async function predictCSV(file: File): Promise<MLPredictionResult[]> {
  const formData = new FormData();
  formData.append('file', file);

  const response = await fetch(`${API_BASE}/predict/csv`, {
    method: 'POST',
    body: formData,
  });

  return parseApiResponse<MLPredictionResult[]>(response, 'Prediction failed');
}

export async function predictSingle(features: Record<string, unknown>): Promise<MLPredictionResult> {
  const response = await fetch(`${API_BASE}/predict/full`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      binary_features: Object.values(features),
      multi_features: features,
      source_ip: '0.0.0.0',
      protocol: 'TCP',
      user_id: 'local_user',
      device_id: 'frontend',
    }),
  });

  return parseApiResponse<MLPredictionResult>(response, 'Prediction failed');
}

export async function getDetectionLogs(limit = 50): Promise<DetectionLog[]> {
  const response = await fetch(`${API_BASE}/api/logs?limit=${limit}`);
  return parseApiResponse<DetectionLog[]>(response, 'Unable to load detection logs');
}

export async function getStatsOverview(): Promise<StatsOverview> {
  const response = await fetch(`${API_BASE}/api/stats/overview`);
  return parseApiResponse<StatsOverview>(response, 'Unable to load statistics');
}

export async function getTimeline(days = 30): Promise<TimelineData[]> {
  const response = await fetch(`${API_BASE}/api/stats/timeline?days=${days}`);
  return parseApiResponse<TimelineData[]>(response, 'Unable to load timeline');
}

export async function getSHAPExplanation(attackType: string, features: Record<string, unknown>): Promise<SHAPExplanation> {
  try {
    const response = await fetch(`${API_BASE}/explain/shap`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ attack_type: attackType, features }),
    });

    if (!response.ok) throw new Error('SHAP explanation failed');

    const payload = await response.json().catch(() => null);
    if (payload?.success) {
      return payload.data as SHAPExplanation;
    }

    return generateMockSHAP(features);
  } catch {
    return generateMockSHAP(features);
  }
}

function generateMockSHAP(features: Record<string, unknown>): SHAPExplanation {
  const featureEntries = Object.entries(features);
  const shapFeatures = featureEntries.map(([key, value]) => ({
    feature: key,
    value: typeof value === 'number' ? value : 0,
    impact: Math.random() > 0.5 ? 'positive' as const : 'negative' as const,
    description: getFeatureDescription(key),
  }));

  shapFeatures.sort((a, b) => Math.abs(b.value) - Math.abs(a.value));

  return {
    base_value: 0.5,
    predicted_value: 0.9,
    features: shapFeatures,
    top_positive: shapFeatures.filter(f => f.impact === 'positive').slice(0, 5),
    top_negative: shapFeatures.filter(f => f.impact === 'negative').slice(0, 5),
  };
}

function getFeatureDescription(feature: string): string {
  const descriptions: Record<string, string> = {
    deltatime_new: 'Time between packets - indicates flood patterns',
    protocol: 'Network protocol type (TCP/UDP/ICMP)',
    tcp_flags: 'TCP flag combination (SYN, ACK, FIN)',
    dest_port: 'Destination port number',
    length: 'Packet payload size',
    is_attack_tool: 'Known attack tool signature detected',
    is_http_request: 'HTTP request pattern identified',
    is_http_error: 'HTTP error response detected',
    ip_ttl: 'IP Time-To-Live value',
  };
  return descriptions[feature] || 'Network traffic feature';
}
