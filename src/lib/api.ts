const API_URL = "http://127.0.0.1:8000";

export interface PredictResult {
  is_attack: boolean;
  attack_type: string;
  severity: string;
  confidence: number | null;
  code: number;
}

export async function predictPacket(features: number[]): Promise<PredictResult> {
  const res = await fetch(`${API_URL}/predict`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ features }),
  });
  if (!res.ok) throw new Error("API error");
  return res.json();
}
