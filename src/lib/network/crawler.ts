import { safeFetch } from "../security/safe-fetch.ts";
import { parseHtml } from "../html/parse.ts";
import { parseRobots, isAllowed, type RobotsParsed } from "../seo/robots.ts";

/**
 * Small, polite, dependency-free site crawler.
 * It only follows links on the same host, honours robots.txt when asked,
 * and stops at a page cap and a wall-clock budget.
 */

export interface CrawlPage {
  url: string;
  status: number;
  title: string | null;
  description: string | null;
  h1: string | null;
  h1Count: number;
  words: number;
  images: number;
  missingAlt: number;
  noindex: boolean;
  canonical: string | null;
  internal: number;
  external: number;
  redirects: number;
  contentType: string;
  bytes: number;
  error?: string;
}

export interface BrokenLink { url: string; status: string; foundOn: string }

export interface CrawlResult {
  host: string;
  pages: CrawlPage[];
  broken: BrokenLink[];
  blockedByRobots: number;
  limitHit: boolean;
  elapsedMs: number;
}

const TRACKING = /^(utm_|fbclid|gclid|msclkid|mc_cid|mc_eid|_ga$|ref$)/i;

/** Resolve, drop fragments/tracking params and normalise a trailing slash. */
export function normalizeCrawlUrl(href: string, base: string): string | null {
  let u: URL;
  try { u = new URL(href, base); } catch { return null; }
  if (u.protocol !== "http:" && u.protocol !== "https:") return null;
  u.hash = "";
  u.hostname = u.hostname.toLowerCase();
  for (const k of [...u.searchParams.keys()]) if (TRACKING.test(k)) u.searchParams.delete(k);
  if (u.pathname !== "/") u.pathname = u.pathname.replace(/\/+$/, "") || "/";
  return u.href;
}

async function pool<T, R>(items: T[], limit: number, fn: (x: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.max(1, Math.min(limit, items.length)) }, async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]);
    }
  });
  await Promise.all(workers);
  return out;
}

export interface CrawlOptions {
  maxPages: number;
  concurrency?: number;
  respectRobots?: boolean;
  timeoutMs?: number;
  budgetMs?: number;
  maxBytes?: number;
}

export async function crawlSite(start: string, opts: CrawlOptions): Promise<CrawlResult> {
  const startedAt = Date.now();
  const maxPages = Math.max(1, Math.min(50, opts.maxPages));
  const concurrency = opts.concurrency ?? 3;
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const budgetMs = opts.budgetMs ?? 55_000;
  const deadline = startedAt + budgetMs;

  const startUrl = normalizeCrawlUrl(start, start);
  if (!startUrl) throw new Error("Enter a valid http(s) URL.");
  let host = new URL(startUrl).hostname;

  let robots: RobotsParsed | null = null;
  if (opts.respectRobots !== false) {
    try {
      const r = await safeFetch(new URL("/robots.txt", startUrl).href, { maxBytes: 300_000, timeoutMs: 8_000 });
      if (r.status === 200) robots = parseRobots(r.body);
    } catch { /* no robots.txt or unreachable: crawl by default */ }
  }

  const seen = new Set<string>([startUrl]);
  const queue: string[] = [startUrl];
  const pages: CrawlPage[] = [];
  let blockedByRobots = 0;

  while (queue.length && pages.length < maxPages && Date.now() < deadline) {
    const batch = queue.splice(0, Math.min(concurrency, maxPages - pages.length));
    const results = await pool(batch, concurrency, async (u): Promise<{ page: CrawlPage; links: string[] } | null> => {
      const parsed = new URL(u);
      if (robots && !isAllowed(robots, "RankacornBot", parsed.pathname + parsed.search).allowed) {
        blockedByRobots++;
        return null;
      }
      try {
        const r = await safeFetch(u, { maxBytes: opts.maxBytes ?? 1_500_000, timeoutMs });
        host = new URL(r.finalUrl).hostname;
        const p = parseHtml(r.body);
        const xrobots = Array.isArray(r.headers["x-robots-tag"]) ? r.headers["x-robots-tag"].join(",") : (r.headers["x-robots-tag"] ?? "");
        const internal: string[] = [];
        let external = 0;
        for (const l of p.links) {
          const n = normalizeCrawlUrl(l.href, r.finalUrl);
          if (!n) continue;
          if (new URL(n).hostname === host) internal.push(n);
          else external++;
        }
        const h1s = p.headings.filter((h) => h.level === 1);
        return {
          page: {
            url: u, status: r.status, title: p.title, description: p.metaDescription,
            h1: h1s[0]?.text ?? null, h1Count: h1s.length, words: p.wordCount,
            images: p.images.length, missingAlt: p.images.filter((i) => i.alt === null).length,
            noindex: /noindex/i.test(p.robotsMeta ?? "") || /noindex/i.test(String(xrobots)),
            canonical: p.canonical, internal: internal.length, external,
            redirects: Math.max(0, r.hops.length - 1),
            contentType: String(r.headers["content-type"] ?? "").split(";")[0],
            bytes: Buffer.byteLength(r.body),
          },
          links: internal,
        };
      } catch (e) {
        return {
          page: {
            url: u, status: 0, title: null, description: null, h1: null, h1Count: 0, words: 0,
            images: 0, missingAlt: 0, noindex: false, canonical: null, internal: 0, external: 0,
            redirects: 0, contentType: "", bytes: 0, error: (e as Error).message,
          },
          links: [],
        };
      }
    });

    for (const res of results) {
      if (!res) continue;
      pages.push(res.page);
      for (const l of res.links.slice(0, 300)) {
        if (seen.has(l) || pages.length + queue.length >= maxPages * 3) continue;
        seen.add(l);
        queue.push(l);
      }
    }
  }

  const broken: BrokenLink[] = pages
    .filter((p) => p.error || p.status === 0 || p.status >= 400)
    .map((p) => ({ url: p.url, status: p.error ? "error" : String(p.status), foundOn: host }));

  return { host, pages, broken, blockedByRobots, limitHit: queue.length > 0, elapsedMs: Date.now() - startedAt };
}
