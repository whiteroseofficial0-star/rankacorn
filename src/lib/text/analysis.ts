const STOP = new Set(
  "a an and are as at be but by for from has have he her his i if in into is it its of on or our she so that the their them they this to was we were what when which who will with you your not no can do does how why".split(" "),
);

export const tokenize = (s: string): string[] => s.toLowerCase().match(/[\p{L}\p{N}']+/gu) ?? [];

export function countText(s: string) {
  const words = tokenize(s);
  const sentences = s.split(/[.!?]+(?:\s|$)/).filter((x) => x.trim()).length;
  const paragraphs = s.split(/\n\s*\n/).filter((x) => x.trim()).length;
  return {
    characters: s.length,
    charactersNoSpaces: s.replace(/\s/g, "").length,
    words: words.length,
    sentences,
    paragraphs,
    readingTimeMinutes: Math.max(words.length ? 1 : 0, Math.round(words.length / 238)),
  };
}

function syllables(word: string): number {
  const w = word.toLowerCase().replace(/[^a-z]/g, "");
  if (!w) return 0;
  if (w.length <= 3) return 1;
  const m = w.replace(/(?:[^laeiouy]es|ed|[^laeiouy]e)$/, "").replace(/^y/, "").match(/[aeiouy]{1,2}/g);
  return Math.max(1, m ? m.length : 1);
}

/** Flesch Reading Ease. English-only heuristic. */
export function readability(s: string) {
  const words = tokenize(s).filter((w) => /[a-z]/i.test(w));
  const sentences = Math.max(1, s.split(/[.!?]+(?:\s|$)/).filter((x) => x.trim()).length);
  if (words.length === 0) return { fleschReadingEase: null, gradeLevel: null, label: "Not enough text", avgWordsPerSentence: 0 };
  const syl = words.reduce((n, w) => n + syllables(w), 0);
  const ease = 206.835 - 1.015 * (words.length / sentences) - 84.6 * (syl / words.length);
  const grade = 0.39 * (words.length / sentences) + 11.8 * (syl / words.length) - 15.59;
  const label = ease >= 90 ? "Very easy" : ease >= 70 ? "Easy" : ease >= 60 ? "Plain English" : ease >= 50 ? "Fairly difficult" : ease >= 30 ? "Difficult" : "Very difficult";
  return { fleschReadingEase: Math.round(ease * 10) / 10, gradeLevel: Math.round(grade * 10) / 10, label, avgWordsPerSentence: Math.round((words.length / sentences) * 10) / 10 };
}

export function keywordFrequency(text: string, opts: { n?: 1 | 2 | 3; removeStopWords?: boolean; top?: number } = {}) {
  const n = opts.n ?? 1;
  const toks = tokenize(text);
  const total = toks.length;
  const counts = new Map<string, number>();
  for (let i = 0; i + n <= toks.length; i++) {
    const gram = toks.slice(i, i + n);
    if (opts.removeStopWords !== false && (STOP.has(gram[0]) || STOP.has(gram[n - 1]))) continue;
    const k = gram.join(" ");
    counts.set(k, (counts.get(k) ?? 0) + 1);
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, opts.top ?? 25)
    .map(([term, count]) => ({ term, count, densityPercent: total ? Math.round((count / total) * 10000) / 100 : 0 }));
}

export function keywordDensity(text: string, keyword: string) {
  const toks = tokenize(text);
  const kw = tokenize(keyword);
  if (!kw.length) return { occurrences: 0, totalWords: toks.length, densityPercent: 0 };
  let occ = 0;
  for (let i = 0; i + kw.length <= toks.length; i++) if (kw.every((w, j) => toks[i + j] === w)) occ++;
  return { occurrences: occ, totalWords: toks.length, densityPercent: toks.length ? Math.round(((occ * kw.length) / toks.length) * 10000) / 100 : 0 };
}

export function keywordPlacement(input: { keyword: string; title?: string; metaDescription?: string; h1?: string; url?: string; body: string }) {
  const kw = input.keyword.toLowerCase().trim();
  const has = (s?: string) => !!s && s.toLowerCase().includes(kw);
  const words = tokenize(input.body);
  const first100 = words.slice(0, 100).join(" ");
  return {
    inTitle: has(input.title),
    inMetaDescription: has(input.metaDescription),
    inH1: has(input.h1),
    inUrl: !!input.url && input.url.toLowerCase().replace(/[-_/]/g, " ").includes(kw),
    inFirst100Words: first100.includes(kw),
    bodyDensity: keywordDensity(input.body, kw),
  };
}

const shingles = (toks: string[], k: number) => {
  const out = new Set<string>();
  for (let i = 0; i + k <= toks.length; i++) out.add(toks.slice(i, i + k).join(" "));
  return out;
};

/** Word-shingle Jaccard similarity plus bag-of-words cosine, 0-100. */
export function textSimilarity(a: string, b: string) {
  const ta = tokenize(a), tb = tokenize(b);
  if (!ta.length || !tb.length) return { jaccardPercent: 0, cosinePercent: 0 };
  const k = Math.min(3, ta.length, tb.length);
  const sa = shingles(ta, k), sb = shingles(tb, k);
  let inter = 0;
  for (const x of sa) if (sb.has(x)) inter++;
  const jaccard = inter / (sa.size + sb.size - inter);
  const fa = new Map<string, number>(), fb = new Map<string, number>();
  ta.forEach((w) => fa.set(w, (fa.get(w) ?? 0) + 1));
  tb.forEach((w) => fb.set(w, (fb.get(w) ?? 0) + 1));
  let dot = 0, na = 0, nb = 0;
  for (const [w, c] of fa) { dot += c * (fb.get(w) ?? 0); na += c * c; }
  for (const c of fb.values()) nb += c * c;
  return { jaccardPercent: Math.round(jaccard * 1000) / 10, cosinePercent: Math.round((dot / Math.sqrt(na * nb)) * 1000) / 10 };
}

export function slugify(s: string, opts: { maxLength?: number; removeStopWords?: boolean } = {}): string {
  let words = s.normalize("NFKD").replace(/[̀-ͯ]/g, "").toLowerCase().replace(/&/g, " and ").replace(/[^a-z0-9]+/g, " ").trim().split(/\s+/).filter(Boolean);
  if (opts.removeStopWords) { const f = words.filter((w) => !STOP.has(w)); if (f.length) words = f; }
  let slug = words.join("-");
  const max = opts.maxLength ?? 80;
  if (slug.length > max) slug = slug.slice(0, max).replace(/-[^-]*$/, "") || slug.slice(0, max);
  return slug;
}
