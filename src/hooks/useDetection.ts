import { useState, useCallback, useEffect } from 'react';
import type { DetectionSession, MLPredictionResult } from '@/types/detection';
import { predictCSV, predictSingle } from '@/services/detectionApi';
import { useDetectionStore } from '@/stores/agentStore';

export function useDetection() {
  const [session, setSession] = useState<DetectionSession | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const store = useDetectionStore();

  useEffect(() => {
    store.restoreCurrentDetection();
  }, [store]);

  const uploadAndAnalyze = useCallback(async (file: File) => {
    setIsAnalyzing(true);
    setError(null);

    try {
      const results = await predictCSV(file);
      const attacks = results.filter((result) => result.is_attack);

      const summary = {
        total_packets: results.length,
        attacks_detected: attacks.length,
        attack_types: attacks.reduce((acc, curr) => {
          const type = curr.attack_type || 'Unknown';
          acc[type] = (acc[type] || 0) + 1;
          return acc;
        }, {} as Record<string, number>),
        max_confidence: attacks.length > 0 ? Math.max(...attacks.map((attack) => attack.confidence ?? 0)) : 0,
        avg_confidence: attacks.length > 0
          ? attacks.reduce((sum, attack) => sum + (attack.confidence ?? 0), 0) / attacks.length
          : 0,
        highest_severity: attacks.length > 0
          ? attacks.reduce((prev, curr) => {
              const sevMap: Record<string, number> = { Critical: 4, High: 3, Medium: 2, Low: 1, Safe: 0 };
              return sevMap[curr.severity || 'Low'] > sevMap[prev] ? curr.severity || 'Low' : prev;
            }, 'Low' as string)
          : 'Safe',
        top_source_ips: [...new Set(attacks.map((attack) => attack.features?.source_ip).filter(Boolean))].slice(0, 5) as string[],
        time_range: {
          start: new Date().toISOString(),
          end: new Date().toISOString(),
        },
      };

      const newSession: DetectionSession = {
        id: crypto.randomUUID(),
        status: 'completed',
        fileName: file.name,
        results,
        summary,
        createdAt: new Date(),
        completedAt: new Date(),
      };

      setSession(newSession);
      const topAttack = attacks[0] as MLPredictionResult | undefined;
      if (topAttack) {
        await store.storeCurrentDetection({
          id: `${topAttack.attack_type ?? 'detection'}-${Date.now()}`,
          attack_type: topAttack.attack_type ?? 'Unknown',
          confidence: topAttack.confidence ?? 0,
          severity: topAttack.severity ?? 'Low',
          source_ip: topAttack.features?.source_ip as string | undefined,
          protocol: topAttack.features?.protocol as string | undefined,
          detected_at: new Date().toISOString(),
          features: topAttack.features as unknown as Record<string, unknown>,
        });
      }
      return newSession;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error';
      setError(message);
      setSession((prev) => (prev ? { ...prev, status: 'error' } : null));
      return null;
    } finally {
      setIsAnalyzing(false);
    }
  }, [store]);

  const getTopAttack = useCallback((): MLPredictionResult | null => {
    if (!session || session.results.length === 0) return null;
    const attacks = session.results.filter((result) => result.is_attack);
    if (attacks.length === 0) return null;
    return attacks.reduce((prev, curr) => ((curr.confidence ?? 0) > (prev.confidence ?? 0) ? curr : prev));
  }, [session]);

  const resetSession = useCallback(() => {
    setSession(null);
    setError(null);
    setIsAnalyzing(false);
  }, []);

  return {
    session,
    isAnalyzing,
    error,
    uploadAndAnalyze,
    getTopAttack,
    resetSession,
    hasAttacks: session ? session.results.some((result) => result.is_attack) : false,
  };
}
