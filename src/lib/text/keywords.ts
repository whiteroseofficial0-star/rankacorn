/**
 * Keyword utilities. Everything here is rule-based text processing.
 * No search volume, CPC or difficulty is produced: those require a data provider.
 */
import { tokenize } from "./analysis.ts";

export function cleanKeywordList(input: string | string[], opts: { lowercase?: boolean } = {}) {
  const raw = Array.isArray(input) ? input : input.split(/\r?\n|,/);
  const seen = new Set<string>();
  const keywords: string[] = [];
  let duplicates = 0;
  for (const r of raw) {
    let k = r.replace(/\s+/g, " ").trim();
    if (opts.lowercase !== false) k = k.toLowerCase();
    if (!k) continue;
    const key = k.toLowerCase();
    if (seen.has(key)) { duplicates++; continue; }
    seen.add(key);
    keywords.push(k);
  }
  return { keywords, duplicatesRemoved: duplicates, total: keywords.length };
}

const QUESTION_PREFIXES = ["what is", "what are", "how to", "how does", "why is", "why do", "when to", "where to", "who is", "which is the best", "can you", "is it worth", "should i"];
const MODIFIERS_SUFFIX = ["for beginners", "for small business", "near me", "online", "free", "tools", "examples", "checklist", "guide", "tips", "step by step", "template", "software", "services", "cost"];
const MODIFIERS_PREFIX = ["best", "top", "cheap", "free", "easy", "how to use", "diy", "professional", "affordable", "local"];

export function questionKeywords(seed: string): string[] {
  const s = seed.trim().toLowerCase();
  if (!s) return [];
  return QUESTION_PREFIXES.map((p) => `${p} ${s}`.replace(/^how to (.+)$/, "how to $1").trim());
}

export function longTailKeywords(seed: string): string[] {
  const s = seed.trim().toLowerCase();
  if (!s) return [];
  return [...MODIFIERS_PREFIX.map((m) => `${m} ${s}`), ...MODIFIERS_SUFFIX.map((m) => `${s} ${m}`)];
}

export type Intent = "informational" | "commercial" | "transactional" | "navigational" | "local";

const SIGNALS: Record<Exclude<Intent, "navigational">, RegExp> = {
  transactional: /\b(buy|order|purchase|coupon|discount|deal|price|pricing|cheap|subscribe|download|sign ?up|hire|book)\b/,
  commercial: /\b(best|top|review|reviews|vs|versus|compare|comparison|alternative|alternatives|worth it)\b/,
  local: /\b(near me|nearby|in my area|open now)\b/,
  informational: /\b(what|how|why|when|who|guide|tutorial|learn|tips|examples?|meaning|definition|ideas?|checklist)\b/,
};

/** Heuristic classifier from wording only; it does not look at actual SERPs. */
export function classifyIntent(keyword: string): { intent: Intent; confidence: "low" | "medium"; matched: string | null } {
  const k = keyword.toLowerCase();
  if (/\b(login|log in|sign in|official site|\w+\.com)\b/.test(k)) return { intent: "navigational", confidence: "medium", matched: "navigational wording" };
  for (const intent of ["local", "transactional", "commercial", "informational"] as const) {
    const m = k.match(SIGNALS[intent]);
    if (m) return { intent, confidence: "medium", matched: m[0] };
  }
  return { intent: "informational", confidence: "low", matched: null };
}

const STOP = new Set("a an the and or of for to in on with is are how what why best top vs near me".split(" "));
const stem = (w: string) => w.replace(/(ing|ers|er|es|s)$/, (m, _x, off: number) => (off >= 3 ? "" : m));

/** Group keywords that share a significant (stemmed) word. Each keyword lands in exactly one cluster. */
export function clusterKeywords(keywords: string[]) {
  const unique = cleanKeywordList(keywords).keywords;
  const tokenSets = unique.map((k) => tokenize(k).filter((w) => !STOP.has(w)).map(stem));
  const freq = new Map<string, number>();
  tokenSets.forEach((set) => new Set(set).forEach((t) => freq.set(t, (freq.get(t) ?? 0) + 1)));
  const clusters = new Map<string, string[]>();
  unique.forEach((kw, i) => {
    const toks = [...new Set(tokenSets[i])];
    const best = toks.filter((t) => (freq.get(t) ?? 0) > 1).sort((a, b) => (freq.get(b)! - freq.get(a)!) || (b.length - a.length))[0];
    const key = best ?? "(ungrouped)";
    (clusters.get(key) ?? clusters.set(key, []).get(key)!).push(kw);
  });
  return [...clusters.entries()]
    .map(([label, items]) => ({ label, keywords: items }))
    .sort((a, b) => (a.label === "(ungrouped)" ? 1 : b.label === "(ungrouped)" ? -1 : b.keywords.length - a.keywords.length));
}
