import type { ParsedPage } from "../html/parse.ts";
import { parseHtml } from "../html/parse.ts";
import { safeFetch } from "../security/safe-fetch.ts";
import { parseRobots, isAllowed } from "./robots.ts";
import { parseSitemap } from "./sitemap.ts";
import { crawlSite } from "../network/crawler.ts";
import { inspectCertificate } from "../network/ssl.ts";
import { lookupRecords } from "../network/dns.ts";
import { gradeSecurityHeaders } from "../network/headers.ts";
import { fetchPageSpeed, type PsiReport } from "../network/pagespeed.ts";

/**
 * One-box site health report: combines the parsers and network checks into a
 * single weighted score. The scoring function is pure so it can be unit-tested.
 */

export type CheckStatus = "pass" | "warning" | "error" | "info" | "unverified";

export interface HealthCheck {
  id: string;
  label: string;
  weight: number;
  status: CheckStatus;
  detail: string;
  why: string;
  fix?: string;
}

export interface HealthInput {
  finalUrl: string;
  status: number;
  headers: Record<string, string | string[] | undefined>;
  page: ParsedPage;
  tls: { trusted: boolean; daysRemaining: number; protocol: string | null } | null;
  dns: { records: number } | null;
  robots: { status: number; disallowsAll: boolean } | null;
  sitemap: { status: number; entries: number; type: string } | null;
  crawl: { pages: number; broken: number; duplicateTitles: number; noindex: number; missingAlt: number } | null;
  pagespeed: PsiReport | null;
}

export interface HealthScore {
  score: number;
  grade: string;
  checks: HealthCheck[];
  topFixes: HealthCheck[];
  max: number;
}

/** Partial credit: a warning still counts for half. Unverified checks never punish. */
const RATIO: Record<CheckStatus, number> = { pass: 1, info: 1, unverified: 1, warning: 0.5, error: 0 };

export function scoreHealth(i: HealthInput): HealthScore {
  const checks: HealthCheck[] = [];
  const add = (c: HealthCheck) => checks.push(c);
  const https = i.finalUrl.toLowerCase().startsWith("https://");

  add({
    id: "https", label: "HTTPS", weight: 10, status: https ? "pass" : "error",
    detail: https ? "Served over HTTPS" : "Served over plain HTTP",
    why: "HTTPS protects visitors and browsers warn on insecure pages.",
    fix: https ? undefined : "Install a TLS certificate and redirect every HTTP URL to HTTPS.",
  });

  add({
    id: "status", label: "Homepage response", weight: 8,
    status: i.status === 200 ? "pass" : i.status >= 400 ? "error" : "warning",
    detail: `HTTP ${i.status}`,
    why: "Search engines cannot index a page that does not return a success status.",
    fix: i.status === 200 ? undefined : "Make the homepage return 200, or redirect it to a working URL.",
  });

  const title = i.page.title?.trim() ?? "";
  add({
    id: "title", label: "Title tag", weight: 9,
    status: !title ? "error" : title.length < 30 || title.length > 60 ? "warning" : "pass",
    detail: title ? `${title.length} chars: ${title}` : "No <title> found",
    why: "The title is the headline of your search result and a strong relevance signal.",
    fix: title ? "Keep titles roughly 30-60 characters and unique per page." : "Add a unique, descriptive <title>.",
  });

  const desc = i.page.metaDescription?.trim() ?? "";
  add({
    id: "meta-description", label: "Meta description", weight: 8,
    status: !desc ? "warning" : desc.length < 70 || desc.length > 160 ? "info" : "pass",
    detail: desc ? `${desc.length} chars` : "Not found",
    why: "Google often uses this text as the search snippet; without it the snippet is out of your control.",
    fix: desc ? undefined : "Write a unique 70-160 character summary for the homepage.",
  });

  const h1 = i.page.headings.filter((h) => h.level === 1).length;
  add({
    id: "h1", label: "H1 heading", weight: 4,
    status: h1 === 1 ? "pass" : h1 === 0 ? "warning" : "info",
    detail: h1 === 1 ? "One H1" : `${h1} H1 headings`,
    why: "The H1 tells users and crawlers what the page is about.",
    fix: h1 === 0 ? "Add one descriptive H1." : undefined,
  });

  add({
    id: "canonical", label: "Canonical tag", weight: 3,
    status: i.page.canonical ? "pass" : "info",
    detail: i.page.canonical ?? "Not found",
    why: "A canonical consolidates duplicate URLs such as parameter and slash variants.",
    fix: i.page.canonical ? undefined : "Add a self-referencing canonical link.",
  });

  add({
    id: "viewport", label: "Mobile viewport", weight: 4,
    status: i.page.viewport ? "pass" : "warning",
    detail: i.page.viewport ?? "Not found",
    why: "Google indexes the mobile version of pages; a viewport tag is required for that rendering.",
    fix: i.page.viewport ? undefined : 'Add <meta name="viewport" content="width=device-width, initial-scale=1">.',
  });

  const psi = i.pagespeed;
  const lcpLab = psi?.lab.find((m) => m.id === "largest-contentful-paint");
  const clsLab = psi?.lab.find((m) => m.id === "cumulative-layout-shift");
  const perf = psi?.performance ?? null;
  const perfStatus: CheckStatus = perf === null ? "unverified" : perf >= 90 ? "pass" : perf >= 50 ? "warning" : "error";
  add({
    id: "lighthouse-performance", label: "PageSpeed score (mobile)", weight: 6, status: perfStatus,
    detail: perf === null
      ? "Not measured: the PageSpeed API was unavailable, quota-limited or timed out. Add PAGESPEED_API_KEY in .env to enable it."
      : `Lighthouse ${perf}/100${lcpLab ? `, lab LCP ${lcpLab.display}` : ""}${clsLab ? `, CLS ${clsLab.display}` : ""}`,
    why: "Google uses page experience signals, so slow pages lose both visitors and rankings.",
    fix: perfStatus === "pass" || perfStatus === "unverified"
      ? undefined
      : psi?.opportunities[0]
        ? `Start with: ${psi.opportunities[0].title} (${psi.opportunities[0].display}).`
        : "Compress images, defer non-critical JavaScript and cache static assets.",
  });

  const field = psi?.field;
  const fieldStatus: CheckStatus = !field ? "unverified" : field.overall === "good" ? "pass" : field.overall === "needs-improvement" ? "warning" : "error";
  add({
    id: "core-web-vitals", label: "Core Web Vitals (field)", weight: 9, status: fieldStatus,
    detail: !psi
      ? "Not measured: the PageSpeed API was unavailable, quota-limited or timed out. Add PAGESPEED_API_KEY in .env to enable it."
      : !field
        ? "No Chrome UX field data yet (Google needs real traffic); the lab score is used instead."
        : `${field.metrics.map((m) => `${m.label} ${m.display}`).join(", ")} (${field.overall})`,
    why: "Core Web Vitals are Google's real-user thresholds for loading, interactivity and visual stability.",
    fix: fieldStatus === "pass" || fieldStatus === "unverified"
      ? undefined
      : "Target good thresholds: LCP under 2.5 s, CLS under 0.1 and INP under 200 ms.",
  });

  const sec = gradeSecurityHeaders(i.headers);
  const secStatus: CheckStatus = sec.grade === "A" || sec.grade === "B" ? "pass" : sec.grade === "C" || sec.grade === "D" ? "warning" : "error";
  const missing = sec.checks.filter((c) => !c.present).map((c) => c.name);
  add({
    id: "security-headers", label: "Security headers", weight: 13, status: secStatus,
    detail: `Grade ${sec.grade} (${sec.score}/${sec.max})${missing.length ? `, missing: ${missing.join(", ")}` : ""}`,
    why: "Missing headers do not rank pages, but they widen the attack surface and can trigger browser warnings.",
    fix: missing.length ? `Add: ${missing.join(", ")}.` : undefined,
  });

  const tlsStatus: CheckStatus = !i.tls ? "unverified" : !i.tls.trusted || i.tls.daysRemaining < 14 ? "error" : i.tls.daysRemaining < 30 ? "warning" : "pass";
  add({
    id: "tls", label: "TLS certificate", weight: 9, status: tlsStatus,
    detail: !i.tls ? "Could not inspect the certificate" : `${i.tls.trusted ? "Trusted" : "Not trusted"}, ${i.tls.daysRemaining} day(s) left, ${i.tls.protocol ?? "unknown protocol"}`,
    why: "An expired or untrusted certificate blocks visitors with a full-page browser warning.",
    fix: tlsStatus === "error" || tlsStatus === "warning" ? "Renew the certificate, serve the full chain and automate renewal." : undefined,
  });

  const robotsStatus: CheckStatus = !i.robots ? "unverified" : i.robots.disallowsAll ? "error" : i.robots.status === 200 ? "pass" : "info";
  add({
    id: "robots", label: "robots.txt", weight: 4, status: robotsStatus,
    detail: !i.robots ? "Could not be fetched" : i.robots.disallowsAll ? "Blocks every crawler from the whole site" : i.robots.status === 200 ? "Present and allows crawling" : `No file (status ${i.robots.status}); crawling is allowed by default`,
    why: "robots.txt controls crawling. A stray 'Disallow: /' removes the site from search.",
    fix: i.robots?.disallowsAll ? "Remove the site-wide Disallow rule." : undefined,
  });

  const sitemapStatus: CheckStatus = !i.sitemap ? "unverified" : i.sitemap.status !== 200 ? "warning" : i.sitemap.entries > 0 ? "pass" : "warning";
  add({
    id: "sitemap", label: "XML sitemap", weight: 4, status: sitemapStatus,
    detail: !i.sitemap ? "Could not be fetched" : i.sitemap.status === 200 ? `/sitemap.xml: ${i.sitemap.entries} ${i.sitemap.type === "sitemapindex" ? "child sitemap(s)" : "URL(s)"}` : `/sitemap.xml returned ${i.sitemap.status}`,
    why: "A sitemap speeds up discovery of new and updated pages.",
    fix: sitemapStatus === "pass" ? undefined : "Publish a valid sitemap at /sitemap.xml and reference it in robots.txt.",
  });

  const crawl = i.crawl;
  const crawlStatus: CheckStatus = !crawl ? "unverified" : crawl.broken > 0 ? "error" : crawl.duplicateTitles > 0 || crawl.noindex > 0 ? "warning" : "pass";
  add({
    id: "crawl", label: "Crawl health", weight: 9, status: crawlStatus,
    detail: !crawl ? "Crawl could not run" : `${crawl.pages} page(s): ${crawl.broken} broken, ${crawl.duplicateTitles} duplicate title(s), ${crawl.noindex} noindex, ${crawl.missingAlt} image(s) without alt`,
    why: "Broken pages, duplicate titles and accidental noindex tags waste crawl budget and hide pages.",
    fix: crawlStatus === "pass" ? undefined : "Fix broken responses first, then make titles unique and remove noindex where it is not intended.",
  });

  const max = checks.reduce((n, c) => n + c.weight, 0);
  const score = Math.round((checks.reduce((n, c) => n + c.weight * RATIO[c.status], 0) / max) * 100);
  const grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F";
  const topFixes = checks
    .filter((c) => c.status === "error" || c.status === "warning")
    .sort((a, b) => b.weight - a.weight)
    .slice(0, 5);
  return { score, grade, checks, topFixes, max };
}

export interface HealthReport extends HealthScore {
  host: string;
  finalUrl: string;
  crawlPages: number;
  dnsRecords: number;
  performance: number | null;
}

/** Collect every signal, then score. Individual failures never abort the report. */
export async function runSiteHealth(input: string): Promise<HealthReport> {
  const target = /^https?:\/\//i.test(input.trim()) ? input.trim() : `https://${input.trim()}`;
  const home = await safeFetch(target, { maxBytes: 2_000_000 });
  const page = parseHtml(home.body);
  const origin = new URL(home.finalUrl).origin;
  const host = new URL(home.finalUrl).hostname;

  const [tlsR, dnsR, robotsR, sitemapR, crawlR, psiR] = await Promise.allSettled([
    inspectCertificate(home.finalUrl),
    lookupRecords(host, "ALL"),
    safeFetch(`${origin}/robots.txt`, { maxBytes: 300_000 }),
    safeFetch(`${origin}/sitemap.xml`, { maxBytes: 3_000_000 }),
    crawlSite(home.finalUrl, { maxPages: 10, respectRobots: true }),
    fetchPageSpeed(home.finalUrl, {
      strategy: "mobile",
      apiKey: process.env.PAGESPEED_API_KEY || undefined,
      timeoutMs: 25_000,
    }),
  ]);

  const tls = tlsR.status === "fulfilled"
    ? { trusted: tlsR.value.trusted, daysRemaining: tlsR.value.daysRemaining, protocol: tlsR.value.protocol }
    : null;
  const dns = dnsR.status === "fulfilled" ? { records: dnsR.value.length } : null;
  const pagespeed = psiR.status === "fulfilled" ? psiR.value : null;

  let robots: HealthInput["robots"] = null;
  if (robotsR.status === "fulfilled") {
    const r = robotsR.value;
    let disallowsAll = false;
    if (r.status === 200) disallowsAll = !isAllowed(parseRobots(r.body), "RankacornBot", "/").allowed;
    robots = { status: r.status, disallowsAll };
  }

  let sitemap: HealthInput["sitemap"] = null;
  if (sitemapR.status === "fulfilled") {
    const r = sitemapR.value;
    if (r.status === 200) {
      const p = parseSitemap(r.body);
      sitemap = { status: 200, entries: p.urls.length, type: p.type };
    } else {
      sitemap = { status: r.status, entries: 0, type: "unknown" };
    }
  }

  let crawl: HealthInput["crawl"] = null;
  if (crawlR.status === "fulfilled") {
    const c = crawlR.value;
    const titles = new Map<string, number>();
    for (const p of c.pages) if (p.title) titles.set(p.title, (titles.get(p.title) ?? 0) + 1);
    crawl = {
      pages: c.pages.length,
      broken: c.broken.length,
      duplicateTitles: [...titles.values()].filter((n) => n > 1).length,
      noindex: c.pages.filter((p) => p.noindex).length,
      missingAlt: c.pages.reduce((n, p) => n + p.missingAlt, 0),
    };
  }

  const scored = scoreHealth({ finalUrl: home.finalUrl, status: home.status, headers: home.headers, page, tls, dns, robots, sitemap, crawl, pagespeed });
  return {
    ...scored,
    host,
    finalUrl: home.finalUrl,
    crawlPages: crawl?.pages ?? 0,
    dnsRecords: dns?.records ?? 0,
    performance: pagespeed?.performance ?? null,
  };
}
