// CYBERSHIELD AI — REFERENCE PROVIDER ARCHITECTURE

// Strategy Pattern: Swap providers without changing UI components.
// Current: StaticReferenceProvider
// Future: RagReferenceProvider, HybridReferenceProvider

import type { Reference, ReferenceProvider } from '@/types/agent';

// Abstract Base Provider 
export abstract class BaseReferenceProvider implements ReferenceProvider {
  abstract readonly name: string;
  abstract readonly isRag: boolean;

  abstract getReferences(attackType: string): Promise<Reference[]> | Reference[];

  // Optional: Search capability for future RAG
  search?(query: string, attackType: string): Promise<Reference[]> {
    throw new Error('Search not implemented');
  }

  // Utility: Sort by relevance (for future RAG scoring)
  protected sortByRelevance(refs: Reference[]): Reference[] {
    return [...refs].sort((a, b) => (b.relevanceScore ?? 0) - (a.relevanceScore ?? 0));
  }

  // Utility: Deduplicate by ID
  protected deduplicate(refs: Reference[]): Reference[] {
    const seen = new Set<string>();
    return refs.filter((ref) => {
      if (seen.has(ref.id)) return false;
      seen.add(ref.id);
      return true;
    });
  }
}

// ── Static Reference Provider (Current Implementation) 
export class StaticReferenceProvider extends BaseReferenceProvider {
  readonly name = 'StaticReferenceProvider';
  readonly isRag = false;

  async getReferences(attackType: string): Promise<Reference[]> {
    // Dynamic import to avoid bundling all references if not needed
    const { getReferencesByAttackType } = await import('@/data/references');
    const refs = getReferencesByAttackType(attackType);
    return this.deduplicate(refs);
  }

  // Static provider can also search within its database
  async search(query: string, attackType: string): Promise<Reference[]> {
    const { getReferencesByAttackType } = await import('@/data/references');
    const refs = getReferencesByAttackType(attackType);
    const lowerQuery = query.toLowerCase();
    return refs.filter(
      (ref) =>
        ref.name.toLowerCase().includes(lowerQuery) ||
        ref.description.toLowerCase().includes(lowerQuery)
    );
  }
}

// ── RAG Reference Provider (Future Implementation) ────────────────────────────
// Uncomment and implement when RAG is ready:
/*
export class RagReferenceProvider extends BaseReferenceProvider {
  readonly name = 'RagReferenceProvider';
  readonly isRag = true;

  constructor(private vectorStore: VectorStore, private embeddingModel: EmbeddingModel) {
    super();
  }

  async getReferences(attackType: string): Promise<Reference[]> {
    const query = await this.embeddingModel.embed(`security references for ${attackType}`);
    const results = await this.vectorStore.similaritySearch(query, 10, { attackType });
    return results.map((r) => ({
      id: r.id,
      name: r.metadata.name,
      description: r.metadata.description,
      url: r.metadata.url,
      source: r.metadata.source,
      icon: r.metadata.icon,
      badgeColor: r.metadata.badgeColor,
      relevanceScore: r.score,
      attackTypes: [attackType],
    }));
  }

  async search(query: string, attackType: string): Promise<Reference[]> {
    const embedding = await this.embeddingModel.embed(query);
    const results = await this.vectorStore.similaritySearch(embedding, 10, { attackType });
    return results.map((r) => ({
      id: r.id,
      name: r.metadata.name,
      description: r.metadata.description,
      url: r.metadata.url,
      source: r.metadata.source,
      icon: r.metadata.icon,
      badgeColor: r.metadata.badgeColor,
      relevanceScore: r.score,
      attackTypes: [attackType],
    }));
  }
}
*/

// ── Hybrid Reference Provider (Future Implementation) ─────────────────────────
// Combines static + RAG results:
/*
export class HybridReferenceProvider extends BaseReferenceProvider {
  readonly name = 'HybridReferenceProvider';
  readonly isRag = true;

  constructor(
    private staticProvider: StaticReferenceProvider,
    private ragProvider: RagReferenceProvider
  ) {
    super();
  }

  async getReferences(attackType: string): Promise<Reference[]> {
    const [staticRefs, ragRefs] = await Promise.all([
      this.staticProvider.getReferences(attackType),
      this.ragProvider.getReferences(attackType),
    ]);
    return this.deduplicate([...staticRefs, ...ragRefs]);
  }
}
*/

// Provider Factory
export type ProviderType = 'static' | 'rag' | 'hybrid';

export class ReferenceProviderFactory {
  private static instance: ReferenceProvider | null = null;

  static getProvider(type: ProviderType = 'static'): ReferenceProvider {
    if (this.instance && this.instance.name.includes(type)) {
      return this.instance;
    }

    switch (type) {
      case 'static':
        this.instance = new StaticReferenceProvider();
        break;
      // case 'rag':
      //   this.instance = new RagReferenceProvider(vectorStore, embeddingModel);
      //   break;
      // case 'hybrid':
      //   this.instance = new HybridReferenceProvider(staticProvider, ragProvider);
      //   break;
      default:
        this.instance = new StaticReferenceProvider();
    }

    return this.instance;
  }

  static reset(): void {
    this.instance = null;
  }
}

// Default Export 
export const referenceProvider = ReferenceProviderFactory.getProvider('static');