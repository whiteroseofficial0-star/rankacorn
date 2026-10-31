import { safeFetch } from "../security/safe-fetch.ts";
import { assertSafeUrl, parseTargetUrl } from "../security/url-guard.ts";
import { ProviderError } from "../errors.ts";

/**
 * Google PageSpeed Insights wrapper. Gives real Lighthouse (lab) numbers plus
 * Chrome UX Report (field) data when Google has enough traffic for the origin.
 * No metric is invented: if the API is down, slow, or quota-limited, the caller
 * receives an error and the health report marks the checks "unverified".
 */

export type PsiRating = "good" | "needs-improvement" | "poor" | "unknown";
export type PsiStrategy = "mobile" | "desktop";

export interface PsiMetric {
  id: string;
  label: string;
  display: string;
  rating: PsiRating;
  source: "field" | "lab";
  fix?: string;
}

export interface PsiField {
  scope: "page" | "origin";
  overall: Exclude<PsiRating, "unknown">;
  metrics: PsiMetric[];
}

export interface PsiOpportunity {
  title: string;
  display: string;
  savingsMs: number;
}

export interface PsiReport {
  finalUrl: string;
  strategy: PsiStrategy;
  performance: number | null;
  field: PsiField | null;
  lab: PsiMetric[];
  opportunities: PsiOpportunity[];
  fetchMs: number;
}

const asRecord = (v: unknown): Record<string, unknown> =>
  v && typeof v === "object" ? (v as Record<string, unknown>) : {};
const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
const str = (v: unknown): string => (typeof v === "string" ? v : "");

/** Lighthouse audit score is 0..1; null means the audit did not run. */
export function ratingFromScore(score: number | null): PsiRating {
  if (score === null) return "unknown";
  return score >= 0.9 ? "good" : score >= 0.5 ? "needs-improvement" : "poor";
}

const FIELD_CATEGORY: Record<string, PsiRating> = { FAST: "good", AVERAGE: "needs-improvement", SLOW: "poor" };

/** CrUX returns CLS as integer hundredths, everything else in milliseconds. */
function formatFieldValue(key: string, value: number): string {
  if (key === "CUMULATIVE_LAYOUT_SHIFT_SCORE") return (value / 100).toFixed(2);
  if (value >= 1000) return `${(value / 1000).toFixed(1)} s`;
  return `${Math.round(value)} ms`;
}

const LAB_AUDITS = [
  ["largest-contentful-paint", "LCP", "Compress the hero image, preload it and serve it from a CDN."],
  ["cumulative-layout-shift", "CLS", "Reserve space for images, ads and embeds; never insert content above existing content."],
  ["total-blocking-time", "TBT", "Split long tasks, defer non-critical JavaScript and drop unused third-party tags."],
  ["first-contentful-paint", "FCP", "Remove render-blocking CSS/JS and reduce server response time."],
  ["speed-index", "Speed Index", "Render above-the-fold content sooner and lazy-load the rest."],
  ["server-response-time", "TTFB (lab)", "Add page caching or a CDN and reduce server processing time."],
] as const;

const FIELD_METRICS = [
  ["LARGEST_CONTENTFUL_PAINT_MS", "LCP"],
  ["CUMULATIVE_LAYOUT_SHIFT_SCORE", "CLS"],
  ["INTERACTION_TO_NEXT_PAINT", "INP"],
  ["FIRST_CONTENTFUL_PAINT_MS", "FCP"],
] as const;

const WORST: Record<Exclude<PsiRating, "unknown">, number> = { good: 0, "needs-improvement": 1, poor: 2 };

function buildField(source: Record<string, unknown>, scope: PsiField["scope"]): PsiField | null {
  const metricsRaw = asRecord(source.metrics);
  const metrics: PsiMetric[] = [];
  for (const [key, label] of FIELD_METRICS) {
    const m = asRecord(metricsRaw[key]);
    const percentile = num(m.percentile);
    if (percentile === null) continue;
    const rating = FIELD_CATEGORY[str(m.category).toUpperCase()] ?? "unknown";
    metrics.push({
      id: key.toLowerCase(),
      label,
      display: formatFieldValue(key, percentile),
      rating,
      source: "field",
    });
  }
  if (!metrics.length) return null;

  const stated = FIELD_CATEGORY[str(source.overall_category).toUpperCase()];
  let overall: Exclude<PsiRating, "unknown"> = stated && stated !== "unknown" ? stated : "good";
  if (!stated || stated === "unknown") {
    for (const m of metrics) {
      if (m.rating !== "unknown" && WORST[m.rating] > WORST[overall]) overall = m.rating;
    }
  }
  return { scope, overall, metrics };
}

/** Pure: converts a raw PSI response into the shape the UI and scorer use. */
export function normalizePsi(raw: unknown, strategy: PsiStrategy, requestedUrl: string): PsiReport {
  const json = asRecord(raw);
  const lh = asRecord(json.lighthouseResult);
  const categories = asRecord(lh.categories);
  if (!Object.keys(categories).length) {
    const message = str(asRecord(asRecord(json.error).data).message) || str(asRecord(json.error).message) || "PageSpeed returned no Lighthouse result.";
    throw new ProviderError(message);
  }

  const perfRaw = num(asRecord(categories.performance).score);
  const performance = perfRaw === null ? null : Math.round(perfRaw * 100);

  const audits = asRecord(lh.audits);
  const lab: PsiMetric[] = [];
  for (const [id, label, fix] of LAB_AUDITS) {
    const a = asRecord(audits[id]);
    const display = str(a.displayValue);
    if (!display) continue;
    lab.push({ id, label, display, rating: ratingFromScore(num(a.score)), source: "lab", fix });
  }

  const pageField = buildField(asRecord(json.loadingExperience), "page");
  const field = pageField ?? buildField(asRecord(json.originLoadingExperience), "origin");

  const opportunities: PsiOpportunity[] = [];
  for (const [id, raw2] of Object.entries(audits)) {
    const a = asRecord(raw2);
    if (asRecord(a.details).type !== "opportunity") continue;
    const savingsMs = num(a.numericValue);
    if (savingsMs === null || savingsMs <= 0) continue;
    opportunities.push({
      title: str(a.title) || id,
      display: str(a.displayValue) || `${Math.round(savingsMs)} ms potential savings`,
      savingsMs,
    });
  }
  opportunities.sort((a, b) => b.savingsMs - a.savingsMs);

  const finalUrl = str(lh.finalUrl) || str(lh.finalDisplayedUrl) || requestedUrl;
  return {
    finalUrl,
    strategy,
    performance: num(asRecord(categories.performance).score) === null ? null : performance,
    field,
    lab,
    opportunities: opportunities.slice(0, 3),
    fetchMs: 0,
  };
}

const QUOTA_MESSAGE = "PageSpeed is out of quota for anonymous requests (Google's shared keyless quota resets daily). Add a free PAGESPEED_API_KEY in .env to make this reliable: https://developers.google.com/speed/docs/insights/v5/get-started";

/** Build the official PageSpeed Insights endpoint for a validated target. */
export function psiApiUrl(target: string, strategy: PsiStrategy, apiKey?: string): string {
  const api = new URL("https://www.googleapis.com/pagespeedonline/v5/runPagespeed");
  api.searchParams.set("url", target);
  api.searchParams.set("strategy", strategy);
  api.searchParams.set("category", "performance");
  if (apiKey) api.searchParams.set("key", apiKey);
  return api.href;
}

export interface FetchPsiOptions {
  strategy?: PsiStrategy;
  apiKey?: string;
  timeoutMs?: number;
}

export async function fetchPageSpeed(input: string, options: FetchPsiOptions = {}): Promise<PsiReport> {
  const strategy = options.strategy ?? "mobile";
  const { url } = parseTargetUrl(input);
  // Validate the target before handing it to Google, so an internal host can
  // never be used as a probe target through the API.
  await assertSafeUrl(url.href);

  const api = new URL(psiApiUrl(url.href, strategy, options.apiKey));

  const started = Date.now();
  const res = await safeFetch(api.href, {
    maxBytes: 8_000_000,
    timeoutMs: options.timeoutMs ?? 45_000,
    headers: { accept: "application/json" },
  });

  if (res.status !== 200) {
    let message = "";
    try {
      const parsed = asRecord(JSON.parse(res.body));
      message = str(asRecord(parsed.error).message) || str(asRecord(asRecord(parsed.error).data).message);
    } catch {
      // Keep the status-only message.
    }
    if (res.status === 429) {
      throw new ProviderError(QUOTA_MESSAGE);
    }
    throw new ProviderError(`PageSpeed API returned ${res.status}${message ? `: ${message.replace(/\.$/, "")}` : ""}.`);
  }

  let json: unknown;
  try {
    json = JSON.parse(res.body);
  } catch {
    throw new ProviderError("PageSpeed returned invalid JSON.");
  }
  const report = normalizePsi(json, strategy, url.href);
  return { ...report, fetchMs: Date.now() - started };
}
