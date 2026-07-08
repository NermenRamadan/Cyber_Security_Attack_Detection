import { useState, useCallback } from 'react';
import { Shield, Activity, Server, Lock, AlertTriangle, FileUp, Wifi } from 'lucide-react';
import { useDetection } from '@/hooks/useDetection';
import { useChat } from '@/hooks/useChat';
import DetectionOverlay from '@/components/DetectionOverlay';
import ChatContainer from '@/components/ChatContainer';
import ExplainableAI from '@/components/ExplainableAI';
import { getSHAPExplanation } from '@/services/detectionApi';
import type { SHAPExplanation } from '@/types/detection';

type View = 'monitor' | 'chat';

function StatCard({ icon: Icon, label, value, color, subtext }: {
  icon: typeof Shield;
  label: string;
  value: string;
  color: string;
  subtext: string;
}) {
  return (
    <div className="bg-slate-800/60 backdrop-blur-sm rounded-xl p-4 border border-slate-700/30 hover:border-slate-600/50 transition-all duration-200 group">
      <div className="flex items-start justify-between">
        <div className={`w-10 h-10 rounded-lg ${color} flex items-center justify-center group-hover:scale-110 transition-transform`}>
          <Icon className="w-5 h-5 text-white" />
        </div>
        <div className="text-right">
          <p className="text-2xl font-bold text-white">{value}</p>
          <p className="text-xs text-slate-400">{label}</p>
        </div>
      </div>
      <p className="text-[10px] text-slate-500 mt-2">{subtext}</p>
    </div>
  );
}

export default function App() {
  const [currentView, setCurrentView] = useState<View>('monitor');
  const [, setShowOverlay] = useState(false);
  const [showXAI, setShowXAI] = useState(false);
  const [shapExplanation, setShapExplanation] = useState<SHAPExplanation | null>(null);

  const {
    session: detectionSession,
    isAnalyzing,
    uploadAndAnalyze,
    getTopAttack,
    resetSession,
  } = useDetection();

  const {
    session: chatSession,
    messages,
    isLoading: chatLoading,
    initializeChat,
    sendMessage,
    sendQuickSuggestion,
    endSession,
  } = useChat();

  const handleFileUpload = useCallback(async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const result = await uploadAndAnalyze(file);
    if (result && result.summary.attacks_detected > 0) {
      setShowOverlay(true);
    }
  }, [uploadAndAnalyze]);

  const handleOpenChat = useCallback(() => {
    const topAttack = getTopAttack();
    if (topAttack) {
      initializeChat(topAttack);
      setShowOverlay(false);
      setCurrentView('chat');
    }
  }, [getTopAttack, initializeChat]);

  const handleNewAnalysis = useCallback(() => {
    endSession();
    resetSession();
    setCurrentView('monitor');
  }, [endSession, resetSession]);

  const handleRequestXAI = useCallback(async () => {
    if (!chatSession) return;
    const detection = chatSession.detectionResult;
    const explanation = await getSHAPExplanation(
      detection.attack_type || 'Unknown',
      detection.features
    );
    setShapExplanation(explanation);
    setShowXAI(true);
  }, [chatSession]);

  // Monitor View
  if (currentView === 'monitor') {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-white">
        {/* Animated Background */}
        <div className="fixed inset-0 overflow-hidden pointer-events-none">
          <div className="absolute top-0 left-1/4 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl" />
          <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-blue-500/5 rounded-full blur-3xl" />
        </div>

        {/* Header */}
        <header className="relative z-10 bg-slate-900/80 backdrop-blur-xl border-b border-slate-700/30">
          <div className="max-w-7xl mx-auto px-4 py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
                  <Shield className="w-7 h-7 text-white" />
                </div>
                <div>
                  <h1 className="text-xl font-bold bg-gradient-to-r from-cyan-400 to-blue-400 bg-clip-text text-transparent">
                    CyberShield AI
                  </h1>
                  <p className="text-xs text-slate-400">ML-Powered Threat Detection</p>
                </div>
              </div>
              <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-800/60 rounded-lg border border-slate-700/30">
                <Activity className="w-4 h-4 text-green-400 animate-pulse" />
                <span className="text-xs text-slate-300">System Active</span>
              </div>
            </div>
          </div>
        </header>

        <div className="relative z-10 max-w-7xl mx-auto px-4 py-6 space-y-6">
          {/* Stats */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <StatCard icon={Server} label="Packets Analyzed" value={detectionSession?.summary.total_packets.toLocaleString() || '0'} color="bg-blue-500/20" subtext="From uploaded captures" />
            <StatCard icon={AlertTriangle} label="Attacks Detected" value={detectionSession?.summary.attacks_detected.toString() || '0'} color="bg-red-500/20" subtext="Requires attention" />
            <StatCard icon={Activity} label="Max Confidence" value={detectionSession ? `${detectionSession.summary.max_confidence.toFixed(1)}%` : '0%'} color="bg-orange-500/20" subtext="Highest threat score" />
            <StatCard icon={Lock} label="ML Models" value="2 Active" color="bg-green-500/20" subtext="Binary + Multiclass" />
          </div>

          {/* Upload Area */}
          <div className="bg-slate-800/40 backdrop-blur-sm border border-slate-700/20 rounded-2xl p-8">
            <div className="flex items-center gap-3 mb-2">
              <Wifi className="w-5 h-5 text-cyan-400" />
              <h2 className="text-lg font-semibold text-white">Upload Network Capture</h2>
            </div>
            <p className="text-sm text-slate-400 mb-6">Upload a Wireshark CSV export for ML analysis</p>

            <label className="flex flex-col items-center justify-center w-full h-48 border-2 border-dashed border-slate-600/50 rounded-2xl cursor-pointer hover:border-cyan-500/50 hover:bg-slate-800/30 transition-all duration-300 group">
              <div className="flex flex-col items-center justify-center pt-5 pb-6">
                <div className="w-16 h-16 rounded-2xl bg-slate-800 group-hover:bg-cyan-500/10 flex items-center justify-center mb-4 transition-colors">
                  <FileUp className="w-8 h-8 text-slate-400 group-hover:text-cyan-400 transition-colors" />
                </div>
                <p className="mb-2 text-sm text-slate-300">
                  <span className="font-semibold">Click to upload</span> or drag and drop
                </p>
                <p className="text-xs text-slate-500">CSV files from Wireshark (max 100MB)</p>
              </div>
              <input
                type="file"
                className="hidden"
                accept=".csv"
                onChange={handleFileUpload}
                disabled={isAnalyzing}
              />
            </label>

            {isAnalyzing && (
              <div className="mt-4 flex items-center gap-3 text-cyan-400">
                <div className="w-5 h-5 border-2 border-cyan-400/30 border-t-cyan-400 rounded-full animate-spin" />
                <span className="text-sm">Analyzing network traffic with ML models...</span>
              </div>
            )}

            {detectionSession && detectionSession.summary.attacks_detected === 0 && (
              <div className="mt-4 flex items-center gap-2 text-green-400 bg-green-500/10 rounded-xl p-4 border border-green-500/20">
                <Shield className="w-5 h-5" />
                <span className="text-sm">No threats detected in this capture. Your network appears safe.</span>
              </div>
            )}
          </div>

          {/* Detection Results Table */}
          {detectionSession && detectionSession.results.length > 0 && (
            <div className="bg-slate-800/40 backdrop-blur-sm border border-slate-700/20 rounded-2xl overflow-hidden">
              <div className="px-6 py-4 border-b border-slate-700/20">
                <h3 className="text-sm font-semibold text-white">Detection Results</h3>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-xs text-slate-400 border-b border-slate-700/20">
                      <th className="px-6 py-3 text-left">Time</th>
                      <th className="px-6 py-3 text-left">Attack Type</th>
                      <th className="px-6 py-3 text-left">Severity</th>
                      <th className="px-6 py-3 text-left">Confidence</th>
                      <th className="px-6 py-3 text-left">Protocol</th>
                      <th className="px-6 py-3 text-left">Port</th>
                    </tr>
                  </thead>
                  <tbody>
                    {detectionSession.results
                      .filter(r => r.is_attack)
                      .slice(0, 20)
                      .map((result, i) => (
                        <tr key={i} className="border-b border-slate-700/10 hover:bg-slate-800/30 transition-colors">
                          <td className="px-6 py-3 text-slate-300">{new Date(result.timestamp).toLocaleTimeString()}</td>
                          <td className="px-6 py-3">
                            <span className="px-2 py-1 bg-red-500/10 text-red-400 rounded-lg text-xs font-medium border border-red-500/20">
                              {result.attack_type}
                            </span>
                          </td>
                          <td className="px-6 py-3">
                            <span className={`px-2 py-1 rounded-lg text-xs font-medium border ${
                              result.severity === 'Critical' ? 'bg-red-500/10 text-red-400 border-red-500/20' :
                              result.severity === 'High' ? 'bg-orange-500/10 text-orange-400 border-orange-500/20' :
                              'bg-yellow-500/10 text-yellow-400 border-yellow-500/20'
                            }`}>
                              {result.severity}
                            </span>
                          </td>
                          <td className="px-6 py-3">
                            <div className="flex items-center gap-2">
                              <div className="w-16 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                                <div
                                  className={`h-full rounded-full ${
                                    result.confidence >= 90 ? 'bg-red-500' :
                                    result.confidence >= 70 ? 'bg-orange-500' :
                                    'bg-yellow-500'
                                  }`}
                                  style={{ width: `${result.confidence}%` }}
                                />
                              </div>
                              <span className="text-xs text-slate-300">{result.confidence.toFixed(1)}%</span>
                            </div>
                          </td>
                          <td className="px-6 py-3 text-slate-300">{result.features?.protocol || 'N/A'}</td>
                          <td className="px-6 py-3 text-slate-300">{result.features?.dest_port || 'N/A'}</td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>

        {/* Detection Overlay */}
        <DetectionOverlay
          session={detectionSession}
          onOpenChat={handleOpenChat}
          onDismiss={() => setShowOverlay(false)}
        />
      </div>
    );
  }

  // Chat View
  if (currentView === 'chat' && chatSession) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-white flex flex-col">
        {/* Animated Background */}
        <div className="fixed inset-0 overflow-hidden pointer-events-none">
          <div className="absolute top-0 left-1/4 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl" />
          <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-blue-500/5 rounded-full blur-3xl" />
        </div>

        <div className="relative z-10 flex-1 flex flex-col max-w-5xl mx-auto w-full h-screen">
          <ChatContainer
            detection={chatSession.detectionResult}
            messages={messages}
            isLoading={chatLoading}
            onSendMessage={sendMessage}
            onSuggestionClick={sendQuickSuggestion}
            onRequestXAI={handleRequestXAI}
            onNewAnalysis={handleNewAnalysis}
            onBack={() => setCurrentView('monitor')}
          />
        </div>

        {/* XAI Modal */}
        <ExplainableAI
          explanation={shapExplanation}
          isOpen={showXAI}
          onClose={() => setShowXAI(false)}
        />
      </div>
    );
  }

  return null;
}
