// ═══════════════════════════════════════════════════════════════════════════════
// CYBERSHIELD AI — RELATED REFERENCES SECTION
// ═══════════════════════════════════════════════════════════════════════════════
// Displays official security references for the detected attack type.
// Architecture: Reads from ReferenceProvider (currently Static, future RAG).
// ═══════════════════════════════════════════════════════════════════════════════

import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ExternalLink,
  Shield,
  Target,
  FileText,
  Lock,
  Building2,
  Landmark,
  ChevronDown,
  BookOpen,
  AlertTriangle,
} from 'lucide-react';
import { referenceProvider } from '@/lib/references/provider';
import { SOURCE_META } from '@/data/references';
import type { Reference, ReferenceSource } from '@/types/agent';

interface RelatedReferencesProps {
  attackType: string;
  className?: string;
}

const sourceIconMap: Record<ReferenceSource, React.ReactNode> = {
  OWASP: <Shield className="h-4 w-4" />,
  MITRE: <Target className="h-4 w-4" />,
  NIST: <FileText className="h-4 w-4" />,
  CVE: <Lock className="h-4 w-4" />,
  Microsoft: <Building2 className="h-4 w-4" />,
  CISA: <Landmark className="h-4 w-4" />,
};

export function RelatedReferences({ attackType, className = '' }: RelatedReferencesProps) {
  const [references, setReferences] = useState<Reference[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [activeFilter, setActiveFilter] = useState<ReferenceSource | 'All'>('All');
  const [error, setError] = useState<string | null>(null);

  const loadReferences = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const refs = await referenceProvider.getReferences(attackType);
      setReferences(refs);
    } catch (err) {
      setError('Failed to load references. Please try again.');
      console.error('Reference loading error:', err);
    } finally {
      setLoading(false);
    }
  }, [attackType]);

  useEffect(() => {
    loadReferences();
  }, [loadReferences]);

  const filteredRefs =
    activeFilter === 'All'
      ? references
      : references.filter((ref) => ref.source === activeFilter);

  const sources = ['All', ...Array.from(new Set(references.map((r) => r.source)))] as const;

  if (loading) {
    return (
      <section className={`${className}`}>
        <div className="flex items-center gap-2 mb-4">
          <BookOpen className="h-5 w-5 text-primary" />
          <h2 className="text-lg font-semibold text-foreground">Related References</h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {[1, 2, 3, 4].map((i) => (
            <div
              key={i}
              className="h-24 rounded-xl bg-white/5 border border-white/10 animate-pulse"
            />
          ))}
        </div>
      </section>
    );
  }

  if (error) {
    return (
      <section className={`${className}`}>
        <div className="flex items-center gap-2 mb-4">
          <BookOpen className="h-5 w-5 text-primary" />
          <h2 className="text-lg font-semibold text-foreground">Related References</h2>
        </div>
        <div className="flex items-center gap-3 p-4 rounded-xl bg-red-500/10 border border-red-500/20">
          <AlertTriangle className="h-5 w-5 text-red-400 shrink-0" />
          <div>
            <p className="text-sm text-red-300">{error}</p>
            <button
              onClick={loadReferences}
              className="mt-2 text-xs text-red-400 hover:text-red-300 underline"
            >
              Retry
            </button>
          </div>
        </div>
      </section>
    );
  }

  if (references.length === 0) {
    return (
      <section className={`${className}`}>
        <div className="flex items-center gap-2 mb-4">
          <BookOpen className="h-5 w-5 text-primary" />
          <h2 className="text-lg font-semibold text-foreground">Related References</h2>
        </div>
        <p className="text-sm text-muted-foreground">
          No references available for this attack type yet.
        </p>
      </section>
    );
  }

  return (
    <section className={`${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <BookOpen className="h-5 w-5 text-primary" />
          <h2 className="text-lg font-semibold text-foreground">Related References</h2>
          <span className="text-xs text-muted-foreground ml-2">
            ({filteredRefs.length} refs)
          </span>
        </div>
      </div>

      {/* Source Filter Chips */}
      <div className="flex flex-wrap gap-2 mb-4">
        {sources.map((source) => (
          <button
            key={source}
            onClick={() => setActiveFilter(source)}
            className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium transition-all duration-200 ${
              activeFilter === source
                ? 'bg-primary/20 text-primary border border-primary/30'
                : 'bg-white/5 text-muted-foreground border border-white/10 hover:bg-white/10 hover:text-foreground'
            }`}
          >
            {source !== 'All' && (
              <span
                className="w-2 h-2 rounded-full"
                style={{ backgroundColor: SOURCE_META[source]?.color || '#888' }}
              />
            )}
            {source === 'All' ? 'All Sources' : SOURCE_META[source]?.label || source}
          </button>
        ))}
      </div>

      {/* References Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <AnimatePresence mode="popLayout">
          {filteredRefs.map((ref, index) => (
            <motion.div
              key={ref.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95 }}
              transition={{ duration: 0.3, delay: index * 0.05 }}
              layout
            >
              <div
                className="group relative rounded-xl border border-white/10 bg-white/[0.03] backdrop-blur-sm overflow-hidden hover:border-white/20 hover:bg-white/[0.05] transition-all duration-300 cursor-pointer"
                onClick={() => setExpandedId(expandedId === ref.id ? null : ref.id)}
              >
                {/* Top accent line */}
                <div
                  className="h-0.5 w-full"
                  style={{ backgroundColor: ref.badgeColor }}
                />

                <div className="p-4">
                  {/* Header: Icon + Badge + Name */}
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-center gap-2.5 min-w-0">
                      <div
                        className="shrink-0 w-8 h-8 rounded-lg flex items-center justify-center"
                        style={{ backgroundColor: `${ref.badgeColor}15` }}
                      >
                        <span className="text-primary-foreground">
                          {sourceIconMap[ref.source] || <BookOpen className="h-4 w-4" />}
                        </span>
                      </div>
                      <div className="min-w-0">
                        <h3 className="text-sm font-medium text-foreground truncate">
                          {ref.name}
                        </h3>
                      </div>
                    </div>

                    {/* Source Badge */}
                    <span
                      className="shrink-0 inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[10px] font-semibold uppercase tracking-wider"
                      style={{
                        backgroundColor: `${ref.badgeColor}15`,
                        color: ref.badgeColor,
                        border: `1px solid ${ref.badgeColor}30`,
                      }}
                    >
                      {ref.source}
                    </span>
                  </div>

                  {/* Description (collapsible) */}
                  <AnimatePresence>
                    {expandedId === ref.id && (
                      <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.2 }}
                        className="overflow-hidden"
                      >
                        <p className="mt-3 text-xs text-muted-foreground leading-relaxed">
                          {ref.description}
                        </p>
                      </motion.div>
                    )}
                  </AnimatePresence>

                  {/* Footer: Expand + Link */}
                  <div className="flex items-center justify-between mt-3">
                    <button
                      className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
                      onClick={(e) => {
                        e.stopPropagation();
                        setExpandedId(expandedId === ref.id ? null : ref.id);
                      }}
                    >
                      <ChevronDown
                        className={`h-3.5 w-3.5 transition-transform duration-200 ${
                          expandedId === ref.id ? 'rotate-180' : ''
                        }`}
                      />
                      {expandedId === ref.id ? 'Less' : 'More'}
                    </button>

                    <a
                      href={ref.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-medium bg-white/5 hover:bg-white/10 text-foreground border border-white/10 hover:border-white/20 transition-all duration-200 group/link"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <ExternalLink className="h-3 w-3" />
                      Open
                      <span className="hidden group-hover/link:inline text-[10px] text-muted-foreground">
                        ↗
                      </span>
                    </a>
                  </div>
                </div>
              </div>
            </motion.div>
          ))}
        </AnimatePresence>
      </div>

      {/* Footer Note */}
      <p className="mt-4 text-[11px] text-muted-foreground/60 text-center">
        References sourced from official security organizations. Click "Open" to view full documentation.
      </p>
    </section>
  );
}