const KEY = 'traceback.recentAnalyses.v1';
const ANALYSis_RE = /^ana_[a-f0-9]{64}$/;

export interface RecentAnalysis {
  analysisId: string;
  openedAt: string;
}

export function loadRecentAnalyses(): RecentAnalysis[] {
  try {
    const parsed = JSON.parse(window.localStorage.getItem(KEY) ?? '[]') as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter((item): item is RecentAnalysis => typeof item === 'object' && item !== null && typeof (item as RecentAnalysis).analysisId === 'string' && ANALYSis_RE.test((item as RecentAnalysis).analysisId))
      .slice(0, 5);
  } catch {return [];}
}

export function saveRecentAnalysis(analysisId: string): void {
  if (!ANALYSis_RE.test(analysisId)) return;
  try {
    const next = [{analysisId, openedAt: new Date().toISOString()}, ...loadRecentAnalyses().filter(item => item.analysisId !== analysisId)].slice(0, 5);
    window.localStorage.setItem(KEY, JSON.stringify(next));
  } catch { /* storage may be unavailable (private mode) */ }
}

export function isValidAnalysisId(value: string): boolean {
  return ANALYSis_RE.test(value);
}
