import { safeFetch, USER_AGENT } from "../lib/security/safe-fetch.ts";
import { parseTargetUrl } from "../lib/security/url-guard.ts";
import { parseHtml } from "../lib/html/parse.ts";
import { analyzePage, summarize, type Finding } from "../lib/seo/analyze.ts";
import { parseRobots, isAllowed, generateRobots } from "../lib/seo/robots.ts";
import { parseSitemap, generateSitemap } from "../lib/seo/sitemap.ts";
import { crawlSite } from "../lib/network/crawler.ts";
import { runSiteHealth } from "../lib/seo/health.ts";
import { lookupRecords, DNS_TYPES, isDomainInput } from "../lib/network/dns.ts";
import { inspectCertificate } from "../lib/network/ssl.ts";
import { rdapLookup } from "../lib/network/rdap.ts";
import { gradeSecurityHeaders } from "../lib/network/headers.ts";
import { fetchPageSpeed } from "../lib/network/pagespeed.ts";
import { toCsv } from "../lib/text/csv.ts";
import { countText, readability, keywordDensity, keywordFrequency, textSimilarity, slugify } from "../lib/text/analysis.ts";
import { cleanKeywordList, classifyIntent, clusterKeywords, questionKeywords, longTailKeywords } from "../lib/text/keywords.ts";
import { schemaMarkup, formatJsonLd, htaccessRedirects, hreflangTags, canonicalTag, webManifest, analyzeUrlParams, urlEncodeDecode, serpSnippet, utmUrl, metaTags, socialPreviewTags, type SchemaType } from "../lib/generators/generators.ts";

export interface Field { name: string; label: string; type: "text" | "url" | "textarea" | "select" | "number"; placeholder?: string; options?: string[]; required?: boolean; help?: string }

export type ToolResult =
  | { kind: "findings"; summary: Record<string, number>; findings: unknown[]; meta?: Record<string, string> }
  | { kind: "table"; columns: string[]; rows: (string | number)[][]; note?: string; csv?: boolean; findings?: Finding[]; summary?: Record<string, number> }
  | { kind: "text"; text: string; filename?: string; mime?: string; note?: string }
  | { kind: "keyvalue"; items: [string, string | number | boolean][]; note?: string };

export interface Tool {
  slug: string; name: string; category: string; summary: string;
  fields: Field[];
  howTo: string[];
  faqs: { q: string; a: string }[];
  related: string[];
  network?: boolean; // makes outbound requests (stricter rate limit)
  heavy?: boolean; // fetches many URLs (strictest rate limit)
  run(input: Record<string, string>): Promise<ToolResult> | ToolResult;
}

const req = (i: Record<string, string>, k: string) => { const v = (i[k] ?? "").trim(); if (!v) throw new UserError(`"${k}" is required.`); return v; };
const lines = (s: string) => s.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
export class UserError extends Error {}

const withScheme = (u: string) => (/^https?:\/\//i.test(u) ? u : `https://${u}`);
const list = (items: string[], max = 5) => items.slice(0, max).join(", ") + (items.length > max ? ` … (+${items.length - max} more)` : "");

async function fetchPage(url: string) {
  const r = await safeFetch(url);
  return r;
}

const URL_FIELD: Field = { name: "url", label: "Page URL", type: "url", placeholder: "https://example.com/", required: true };
const TEXT_FIELD: Field = { name: "text", label: "Your text", type: "textarea", required: true };
const KW_LIST: Field = { name: "keywords", label: "Keywords (one per line)", type: "textarea", required: true };
const mkFaq = (q: string, a: string) => ({ q, a });

export const CATEGORIES = ["Website Analysis", "Site Audit & Crawling", "Keyword Tools", "Content Tools", "Technical SEO", "Domain & Security", "Link & Status Utilities"] as const;

export const TOOLS: Tool[] = [
  {
    slug: "site-health-report", name: "Site Health Report", category: "Website Analysis", network: true, heavy: true,
    summary: "One box, one click: a graded A–F report covering HTTPS, DNS, TLS, security headers, robots.txt, sitemap, on-page basics, Core Web Vitals and a 10-page crawl.",
    fields: [{ name: "url", label: "Website URL", type: "url", placeholder: "https://example.com", required: true, help: "Runs a 10-page crawl plus DNS, TLS, robots.txt, sitemap, header and PageSpeed checks." }],
    howTo: ["Enter your homepage URL.", "Press Run tool. PageSpeed alone can take 10-20 seconds.", "Work down the list from error to warning.", "Use Print / Save PDF to keep the report."],
    faqs: [
      mkFaq("How long does it take?", "Usually 10-30 seconds: one page fetch, DNS and TLS lookups, robots.txt, sitemap, up to 10 crawled pages and Google's PageSpeed API, which is often the slowest step."),
      mkFaq("Why is my grade not 100?", "Each check is weighted. Detail lines explain exactly what was found and what to fix; unverified checks never lower the score."),
      mkFaq("Does it use Google PageSpeed?", "Yes. The Lighthouse score and Chrome UX Core Web Vitals come from the official PageSpeed Insights API. If that API times out or is rate-limited, those two checks are marked not measured and do not lower your grade."),
      mkFaq("Does it crawl the whole site?", "No. It crawls up to 10 pages to sample site-wide issues. Use the Site Crawler for up to 50 pages."),
    ],
    related: ["pagespeed-insights", "site-crawler-audit", "security-headers-grader"],
    async run(i) {
      const r = await runSiteHealth(req(i, "url"));
      const findings: Finding[] = r.checks.map((c) => ({
        id: c.id,
        title: `${c.label} — ${c.status === "pass" ? "OK" : c.status === "unverified" ? "not verified" : c.status}`,
        severity: c.status,
        detected: c.detail,
        why: c.why,
        fix: c.status === "pass" ? undefined : c.fix,
      }));
      return {
        kind: "findings", summary: summarize(findings), findings,
        meta: {
          Grade: r.grade, Score: `${r.score}/100`, "Pages crawled": String(r.crawlPages),
          "DNS records": String(r.dnsRecords), PageSpeed: r.performance === null ? "not measured" : `${r.performance}/100`,
          "Top fix": r.topFixes[0]?.fix ?? "None found", "Final URL": r.finalUrl,
        },
      };
    },
  },
  {
    slug: "pagespeed-insights", name: "PageSpeed & Core Web Vitals Checker", category: "Website Analysis", network: true, heavy: true,
    summary: "Official Google PageSpeed Insights data: Lighthouse performance score, real Chrome UX field metrics (LCP, CLS, INP) and the biggest opportunities.",
    fields: [
      { name: "url", label: "Page URL", type: "url", placeholder: "https://example.com/", required: true, help: "Google's anonymous PageSpeed quota is shared by everyone; PAGESPEED_API_KEY in .env makes this reliable." },
      { name: "strategy", label: "Device", type: "select", options: ["mobile", "desktop"], help: "Google indexes the mobile version, so mobile is the realistic default." },
    ],
    howTo: ["Enter the page URL.", "Pick mobile or desktop.", "Press Run tool. The first run for a URL can take 10-30 seconds.", "Fix the largest opportunity first, then re-run."],
    faqs: [
      mkFaq("Where do these numbers come from?", "The official PageSpeed Insights API: Lighthouse runs a real browser for the lab score, and the Chrome UX Report supplies field data from real visitors."),
      mkFaq("Why is there no field data?", "Google only publishes Core Web Vitals for sites with enough real traffic. Low-traffic sites get lab data only; nothing is estimated or faked."),
      mkFaq("Do I need an API key?", "Not strictly, but use one: Google's anonymous quota is shared by all keyless users and is often exhausted. A free key in PAGESPEED_API_KEY raises the limit. When the anonymous quota is gone the tool says so instead of guessing."),
      mkFaq("How is this different from the Site Health Report?", "This tool goes deep on one page and one device. The Site Health Report samples the whole site and folds a mobile PageSpeed summary into its grade."),
    ],
    related: ["site-health-report", "website-seo-checker", "site-crawler-audit"],
    async run(i) {
      const strategy = req(i, "strategy") === "desktop" ? "desktop" : "mobile";
      const r = await fetchPageSpeed(req(i, "url"), {
        strategy,
        apiKey: process.env.PAGESPEED_API_KEY || undefined,
        timeoutMs: 60_000,
      });

      const rows: (string | number)[][] = [
        ...(r.field?.metrics ?? []).map((m) => [m.label, m.display, m.rating, "Chrome UX (field)"]),
        ...r.lab.map((m) => [m.label, m.display, m.rating, "Lighthouse (lab)"]),
      ];

      const findings: Finding[] = [];
      for (const m of r.lab) {
        if (m.rating !== "needs-improvement" && m.rating !== "poor") continue;
        findings.push({
          id: m.id,
          title: `${m.label} ${m.rating === "poor" ? "is poor" : "needs improvement"}`,
          severity: m.rating === "poor" ? "error" : "warning",
          detected: m.display,
          why: m.id === "cumulative-layout-shift"
            ? "Layout shifts make buttons move while people tap them."
            : "This lab metric directly affects how fast the page feels.",
          fix: m.fix,
        });
      }
      if (r.field && r.field.overall !== "good") {
        findings.push({
          id: "field-cwv",
          title: `Real-user Core Web Vitals: ${r.field.overall}`,
          severity: r.field.overall === "poor" ? "error" : "warning",
          detected: r.field.metrics.map((m) => `${m.label} ${m.display}`).join(", "),
          why: "Google's page experience signal uses these real-visitor thresholds, not the lab score.",
          fix: "Target LCP under 2.5 s, CLS under 0.1 and INP under 200 ms for the 75th percentile.",
        });
      }
      if (!r.field) {
        findings.push({
          id: "field-data",
          title: "No Chrome UX field data",
          severity: "info",
          why: "Google needs enough real traffic before it publishes field Core Web Vitals. The lab score is still valid.",
          fix: "Use Search Console's Core Web Vitals report once the site has traffic.",
        });
      }

      const top = r.opportunities[0];
      return {
        kind: "table",
        columns: ["Metric", "Value", "Rating", "Source"],
        rows,
        csv: true,
        findings,
        summary: summarize(findings),
        note: `Google PageSpeed Insights · ${strategy} · ${r.performance === null ? "no score" : `${r.performance}/100`} · ${Math.round(r.fetchMs / 1000)}s${top ? ` · biggest opportunity: ${top.title} (${top.display})` : ""}`,
      };
    },
  },
  {
    slug: "website-seo-checker", name: "Website SEO Checker", category: "Website Analysis", network: true,
    summary: "Fetch a page and check title, meta description, headings, images, canonical, indexability, social tags and structured data.",
    fields: [URL_FIELD],
    howTo: ["Enter the full page URL.", "Review errors first, then warnings.", "Items marked 'Not verified' were not measured by this tool; use the dedicated tool or a provider."],
    faqs: [mkFaq("Does this check Core Web Vitals?", "Not here: this is a fast HTML check. The PageSpeed & Core Web Vitals tool and the Site Health Report call Google's PageSpeed API for real lab and field data."), mkFaq("Does it run JavaScript?", "No. It analyses the HTML the server returns, which is what most crawlers read first.")],
    related: ["robots-txt-checker", "http-status-checker", "serp-snippet-preview"],
    async run(i) {
      const r = await fetchPage(req(i, "url"));
      const p = parseHtml(r.body);
      const findings = analyzePage(p, { finalUrl: r.finalUrl, status: r.status, headers: r.headers, redirectHops: r.hops.length - 1 });
      return { kind: "findings", summary: summarize(findings), findings, meta: { "Final URL": r.finalUrl, "Fetched": new Date().toISOString(), "Response time": `${r.totalMs} ms`, ...(r.truncated ? { Note: "Page exceeded the size limit and was truncated." } : {}) } };
    },
  },
  {
    slug: "http-status-checker", name: "HTTP Status & Redirect Checker", category: "Link & Status Utilities", network: true,
    summary: "Check the status code of one or more URLs and see the full redirect chain.",
    fields: [{ name: "urls", label: "URLs (one per line, max 20)", type: "textarea", required: true }],
    howTo: ["Paste up to 20 URLs.", "Each row shows the final status, hop count and chain.", "Aim for a single 301 at most."],
    faqs: [mkFaq("Why limit to 20 URLs?", "To protect target sites and this service from abuse. Higher limits belong in a paid tier."), mkFaq("Are private addresses allowed?", "No. Localhost and internal networks are blocked for security.")],
    related: ["website-seo-checker", "url-list-cleaner"],
    async run(i) {
      const urls = cleanKeywordList(lines(req(i, "urls")), { lowercase: false }).keywords.slice(0, 20);
      const rows: (string | number)[][] = [];
      for (const u of urls) {
        try {
          const r = await safeFetch(u, { method: "GET", maxBytes: 20_000 });
          rows.push([u, r.status, r.hops.length - 1, r.hops.map((h) => `${h.status} ${h.url}`).join(" → "), r.finalUrl]);
        } catch (e) { rows.push([u, "error", 0, (e as Error).message, ""]); }
      }
      return { kind: "table", columns: ["URL", "Status", "Redirects", "Chain", "Final URL"], rows, csv: true };
    },
  },
  {
    slug: "http-header-analyzer", name: "HTTP Response Header Analyzer", category: "Technical SEO", network: true,
    summary: "Inspect response headers and flag missing security and caching headers.",
    fields: [URL_FIELD], howTo: ["Enter a URL.", "Review the headers returned.", "Add missing security headers at your server or CDN."],
    faqs: [mkFaq("Which headers are checked?", "Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Cache-Control and X-Robots-Tag.")],
    related: ["website-seo-checker", "http-status-checker"],
    async run(i) {
      const r = await safeFetch(req(i, "url"), { maxBytes: 10_000 });
      const want = ["strict-transport-security", "content-security-policy", "x-content-type-options", "x-frame-options", "referrer-policy", "cache-control", "x-robots-tag"];
      const rows = want.map((h) => [h, r.headers[h] ? String(r.headers[h]) : "(not set)"]);
      const others = Object.entries(r.headers).filter(([k]) => !want.includes(k)).map(([k, v]) => [k, String(v)]);
      return { kind: "table", columns: ["Header", "Value"], rows: [...rows, ...others] };
    },
  },
  {
    slug: "robots-txt-checker", name: "Robots.txt Checker & Tester", category: "Technical SEO", network: true,
    summary: "Fetch a site's robots.txt, list its rules and test whether a path is allowed for a user-agent.",
    fields: [{ name: "url", label: "Site URL", type: "url", placeholder: "https://example.com", required: true }, { name: "path", label: "Path to test", type: "text", placeholder: "/private/page.html" }, { name: "agent", label: "User-agent", type: "text", placeholder: "Googlebot" }],
    howTo: ["Enter the site's address.", "Optionally enter a path and user-agent to test.", "Fix warnings before deploying changes."],
    faqs: [mkFaq("Does robots.txt remove pages from Google?", "No. It controls crawling, not indexing. Use noindex or removal tools for that."), mkFaq("Which matching rules are used?", "Longest matching rule wins, Allow wins ties, and * and $ wildcards are supported (Google-style).")],
    related: ["robots-txt-generator", "xml-sitemap-validator"],
    async run(i) {
      const base = new URL(/^https?:\/\//i.test(req(i, "url")) ? i.url.trim() : `https://${i.url.trim()}`);
      const r = await safeFetch(new URL("/robots.txt", base).href, { maxBytes: 500_000 });
      if (r.status === 404) return { kind: "keyvalue", items: [["robots.txt", "Not found (404). Crawlers will assume everything is allowed."]] };
      if (r.status >= 400) return { kind: "keyvalue", items: [["robots.txt", `Returned status ${r.status}`]] };
      const parsed = parseRobots(r.body);
      const items: [string, string | number | boolean][] = [["Fetched from", r.finalUrl], ["Groups", parsed.groups.length], ["Sitemaps", parsed.sitemaps.join(", ") || "none declared"], ["Warnings", parsed.warnings.join(" | ") || "none"]];
      if (i.path?.trim()) {
        const t = isAllowed(parsed, i.agent?.trim() || "*", i.path.trim());
        items.push(["Test", `${i.agent?.trim() || "*"} ${t.allowed ? "ALLOWED" : "BLOCKED"} on ${i.path.trim()}${t.matchedRule ? ` (rule: ${t.matchedRule.type}: ${t.matchedRule.path})` : " (no matching rule)"}`]);
      }
      return { kind: "text", text: r.body, note: items.map(([k, v]) => `${k}: ${v}`).join("\n") };
    },
  },
  {
    slug: "xml-sitemap-validator", name: "XML Sitemap Validator", category: "Technical SEO", network: true,
    summary: "Validate a sitemap from a URL or pasted XML, and extract its URLs.",
    fields: [{ name: "url", label: "Sitemap URL", type: "url", placeholder: "https://example.com/sitemap.xml" }, { name: "xml", label: "…or paste sitemap XML", type: "textarea" }],
    howTo: ["Enter a sitemap URL or paste XML.", "Review errors and warnings.", "Download the extracted URL list as CSV."],
    faqs: [mkFaq("What is validated?", "Root element, loc validity, duplicates, lastmod format, changefreq, priority range and the 50,000 entry limit. It does not request each URL.")],
    related: ["xml-sitemap-generator", "robots-txt-checker"],
    async run(i) {
      let xml = i.xml?.trim();
      if (!xml) { const r = await safeFetch(req(i, "url"), { maxBytes: 5_000_000 }); if (r.status >= 400) throw new UserError(`Sitemap returned status ${r.status}.`); xml = r.body; }
      const p = parseSitemap(xml);
      return { kind: "table", columns: ["URL", "lastmod", "changefreq", "priority"], rows: p.urls.map((u) => [u.loc, u.lastmod ?? "", u.changefreq ?? "", u.priority ?? ""]), csv: true, note: `Type: ${p.type}. ${p.urls.length} entries. Errors: ${p.errors.join(" | ") || "none"}. Warnings: ${p.warnings.slice(0, 10).join(" | ") || "none"}.` };
    },
  },
  {
    slug: "xml-sitemap-generator", name: "XML Sitemap Generator", category: "Technical SEO",
    summary: "Turn a list of URLs into a valid sitemap.xml file.",
    fields: [{ name: "urls", label: "URLs (one per line)", type: "textarea", required: true }, { name: "changefreq", label: "Change frequency", type: "select", options: ["", "daily", "weekly", "monthly", "yearly"] }],
    howTo: ["Paste your canonical URLs.", "Download sitemap.xml.", "Upload it to your site root and reference it in robots.txt."],
    faqs: [mkFaq("Should I include every URL?", "Include only canonical, indexable pages that return 200. Review the file before deploying.")],
    related: ["xml-sitemap-validator", "robots-txt-generator"],
    run(i) {
      const urls = cleanKeywordList(lines(req(i, "urls")), { lowercase: false }).keywords.map((u) => new URL(/^https?:\/\//i.test(u) ? u : `https://${u}`).href);
      if (urls.length > 50000) throw new UserError("A sitemap can hold at most 50,000 URLs.");
      return { kind: "text", text: generateSitemap(urls.map((loc) => ({ loc, changefreq: i.changefreq || undefined }))), filename: "sitemap.xml", mime: "application/xml", note: "Review before deploying." };
    },
  },
  {
    slug: "robots-txt-generator", name: "Robots.txt Generator", category: "Technical SEO",
    summary: "Build a robots.txt file with disallow rules and sitemap references.",
    fields: [{ name: "disallow", label: "Disallow paths (one per line)", type: "textarea", placeholder: "/admin/\n/cart/" }, { name: "allow", label: "Allow paths (one per line)", type: "textarea" }, { name: "sitemaps", label: "Sitemap URLs (one per line)", type: "textarea" }, { name: "agent", label: "User-agent", type: "text", placeholder: "*" }],
    howTo: ["List paths to block.", "Add your sitemap URL.", "Download and place at /robots.txt on your domain root."],
    faqs: [mkFaq("Can a bad robots.txt hurt me?", "Yes. 'Disallow: /' blocks the whole site from crawling. Review and test before deploying.")],
    related: ["robots-txt-checker", "xml-sitemap-generator"],
    run: (i) => ({ kind: "text", text: generateRobots({ allowAll: true, disallow: lines(i.disallow ?? ""), allow: lines(i.allow ?? ""), sitemaps: lines(i.sitemaps ?? ""), userAgent: i.agent?.trim() }), filename: "robots.txt", mime: "text/plain", note: "Review before deploying." }),
  },
  {
    slug: "word-counter", name: "Word & Character Counter", category: "Content Tools",
    summary: "Count words, characters, sentences, paragraphs and reading time.", fields: [TEXT_FIELD],
    howTo: ["Paste text.", "Read the counts."], faqs: [mkFaq("How is reading time estimated?", "At about 238 words per minute.")], related: ["readability-checker", "keyword-density-checker"],
    run: (i) => ({ kind: "keyvalue", items: Object.entries(countText(req(i, "text"))) as [string, number][] }),
  },
  {
    slug: "readability-checker", name: "Readability Checker", category: "Content Tools",
    summary: "Flesch Reading Ease and grade level for English text.", fields: [TEXT_FIELD],
    howTo: ["Paste at least a few sentences.", "Aim for 60+ for general audiences."], faqs: [mkFaq("Is it accurate for other languages?", "No. The syllable heuristic is English-only.")], related: ["word-counter"],
    run: (i) => { const r = readability(req(i, "text")); return { kind: "keyvalue", items: [["Flesch reading ease", r.fleschReadingEase ?? "n/a"], ["Grade level", r.gradeLevel ?? "n/a"], ["Rating", r.label], ["Avg words per sentence", r.avgWordsPerSentence]] }; },
  },
  {
    slug: "keyword-density-checker", name: "Keyword Density Checker", category: "Keyword Tools",
    summary: "Measure how often a keyword appears, and list your most frequent terms.",
    fields: [{ name: "keyword", label: "Target keyword", type: "text" }, TEXT_FIELD, { name: "n", label: "Phrase length", type: "select", options: ["1", "2", "3"] }],
    howTo: ["Paste your copy.", "Optionally enter a target keyword.", "Choose 1-3 word phrases for the frequency table."],
    faqs: [mkFaq("What density should I target?", "There is no ideal percentage. Write naturally; use this to spot over-repetition.")], related: ["keyword-placement-analyzer", "word-counter"],
    run(i) {
      const text = req(i, "text");
      const rows = keywordFrequency(text, { n: (Number(i.n) || 1) as 1 | 2 | 3 }).map((r) => [r.term, r.count, r.densityPercent + "%"]);
      const d = i.keyword?.trim() ? keywordDensity(text, i.keyword) : null;
      return { kind: "table", columns: ["Term", "Count", "Density"], rows, csv: true, note: d ? `"${i.keyword}" appears ${d.occurrences} time(s) in ${d.totalWords} words (${d.densityPercent}%).` : undefined };
    },
  },
  {
    slug: "keyword-list-cleaner", name: "Keyword List Cleaner & Deduplicator", category: "Keyword Tools",
    summary: "Trim, lowercase and remove duplicate keywords from a bulk list.", fields: [KW_LIST],
    howTo: ["Paste keywords separated by new lines or commas.", "Copy or download the cleaned list."], faqs: [mkFaq("What is the size limit?", "Request bodies are capped at 1 MB.")], related: ["keyword-clustering-tool"],
    run(i) { const r = cleanKeywordList(req(i, "keywords")); return { kind: "table", columns: ["Keyword"], rows: r.keywords.map((k) => [k]), csv: true, note: `${r.total} unique keywords; ${r.duplicatesRemoved} duplicates removed.` }; },
  },
  {
    slug: "keyword-clustering-tool", name: "Keyword Clustering Tool", category: "Keyword Tools",
    summary: "Group a keyword list by shared words. Text-based grouping, not SERP-based.", fields: [KW_LIST],
    howTo: ["Paste a keyword list.", "Review the groups.", "Map each group to a page."], faqs: [mkFaq("Is this SERP clustering?", "No. It groups by shared word stems. SERP-overlap clustering needs a data provider, which is not configured.")], related: ["search-intent-classifier", "keyword-list-cleaner"],
    run(i) { const c = clusterKeywords(lines(req(i, "keywords"))); return { kind: "table", columns: ["Cluster", "Keyword"], rows: c.flatMap((x) => x.keywords.map((k) => [x.label, k])), csv: true }; },
  },
  {
    slug: "search-intent-classifier", name: "Search Intent Classifier", category: "Keyword Tools",
    summary: "Label keywords as informational, commercial, transactional, navigational or local from their wording.", fields: [KW_LIST],
    howTo: ["Paste keywords.", "Check the label and matched signal.", "Verify against the real SERP before deciding."], faqs: [mkFaq("How reliable is it?", "It is a wording heuristic only and does not inspect live results.")], related: ["keyword-clustering-tool"],
    run(i) { return { kind: "table", columns: ["Keyword", "Intent", "Confidence", "Matched"], rows: lines(req(i, "keywords")).map((k) => { const r = classifyIntent(k); return [k, r.intent, r.confidence, r.matched ?? ""]; }), csv: true }; },
  },
  {
    slug: "keyword-suggestion-generator", name: "Long-tail & Question Keyword Generator", category: "Keyword Tools",
    summary: "Expand a seed keyword with common modifiers and question formats. No search volume is shown.",
    fields: [{ name: "seed", label: "Seed keyword", type: "text", required: true }],
    howTo: ["Enter a seed.", "Export ideas.", "Validate demand in a keyword data tool."], faqs: [mkFaq("Why no volume or difficulty?", "Those figures need a licensed data provider. None is configured, so none are shown.")], related: ["keyword-clustering-tool"],
    run(i) { const s = req(i, "seed"); return { kind: "table", columns: ["Type", "Keyword"], rows: [...longTailKeywords(s).map((k) => ["long-tail", k]), ...questionKeywords(s).map((k) => ["question", k])], csv: true, note: "Pattern-based ideas; not real search data." }; },
  },
  {
    slug: "slug-generator", name: "SEO-Friendly URL Slug Generator", category: "Content Tools",
    summary: "Convert a title into a clean, lowercase, hyphenated slug.", fields: [{ name: "title", label: "Title", type: "text", required: true }, { name: "stop", label: "Remove stop words", type: "select", options: ["no", "yes"] }],
    howTo: ["Paste a title.", "Copy the slug."], faqs: [mkFaq("Should I change live URLs?", "Only with a 301 redirect from the old URL.")], related: ["serp-snippet-preview"],
    run: (i) => ({ kind: "text", text: slugify(req(i, "title"), { removeStopWords: i.stop === "yes" }) }),
  },
  {
    slug: "text-similarity-checker", name: "Text Similarity Checker", category: "Content Tools",
    summary: "Compare two texts for overlap using shingle Jaccard and cosine similarity.", fields: [{ name: "a", label: "Text A", type: "textarea", required: true }, { name: "b", label: "Text B", type: "textarea", required: true }],
    howTo: ["Paste both texts.", "High percentages suggest duplicated content."], faqs: [mkFaq("Is this a plagiarism checker?", "No. It only compares the two texts you provide.")], related: ["word-counter"],
    run(i) { const r = textSimilarity(req(i, "a"), req(i, "b")); return { kind: "keyvalue", items: [["Shingle overlap (Jaccard)", r.jaccardPercent + "%"], ["Word-frequency cosine", r.cosinePercent + "%"]] }; },
  },
  {
    slug: "serp-snippet-preview", name: "SERP Snippet Preview", category: "Content Tools",
    summary: "Preview how a title and description may be truncated in search results.", fields: [{ name: "title", label: "Title", type: "text", required: true }, { name: "description", label: "Meta description", type: "textarea" }, { name: "url", label: "URL", type: "url", required: true }],
    howTo: ["Enter your title, description and URL.", "Check for truncation."], faqs: [mkFaq("Is the preview exact?", "No. Google truncates by pixel width and may rewrite snippets.")], related: ["slug-generator", "website-seo-checker"],
    run(i) { const s = serpSnippet(req(i, "title"), i.description ?? "", req(i, "url")); return { kind: "keyvalue", items: [["URL", s.displayUrl], ["Title", s.title], ["Description", s.description], ["Title truncated", s.titleTruncated], ["Description truncated", s.descriptionTruncated]], note: s.note }; },
  },
  {
    slug: "schema-markup-generator", name: "Schema Markup (JSON-LD) Generator", category: "Technical SEO",
    summary: "Generate JSON-LD for Article, FAQ, Organization, LocalBusiness, Product and breadcrumbs.",
    fields: [{ name: "type", label: "Type", type: "select", options: ["Article", "FAQPage", "Organization", "LocalBusiness", "Product", "BreadcrumbList"] }, { name: "data", label: "Fields as JSON", type: "textarea", placeholder: '{"headline":"My post","author":"Jane"}', help: "FAQPage: {\"faqs\":[{\"question\":\"...\",\"answer\":\"...\"}]}. BreadcrumbList: {\"items\":[{\"name\":\"Home\",\"url\":\"https://…\"}]}" }],
    howTo: ["Choose a type.", "Supply fields as JSON.", "Test the output in Google's Rich Results Test."], faqs: [mkFaq("Does valid markup guarantee rich results?", "No. Eligibility depends on Google's guidelines and the page content.")], related: ["json-ld-validator"],
    run(i) { let d: Record<string, unknown>; try { d = JSON.parse(i.data || "{}"); } catch { throw new UserError("Fields must be valid JSON."); } try { return { kind: "text", text: schemaMarkup((i.type || "Article") as SchemaType, d), filename: "schema.html", mime: "text/html", note: "Review before deploying." }; } catch (e) { throw new UserError((e as Error).message); } },
  },
  {
    slug: "json-ld-validator", name: "JSON-LD Formatter & Validator", category: "Technical SEO",
    summary: "Check JSON-LD syntax, format it and list its @type values.", fields: [{ name: "json", label: "JSON-LD", type: "textarea", required: true }],
    howTo: ["Paste the JSON (without script tags).", "Fix syntax errors.", "Validate eligibility in Google's Rich Results Test."], faqs: [mkFaq("What does this check?", "JSON syntax, @context and @type presence. It does not check schema.org property rules.")], related: ["schema-markup-generator"],
    run(i) { const r = formatJsonLd(req(i, "json")); if (!r.ok) throw new UserError(`Invalid JSON: ${r.error}`); return { kind: "text", text: r.formatted, note: `Types: ${r.types.join(", ") || "none"}. Warnings: ${r.warnings.join(" | ") || "none"}.` }; },
  },
  {
    slug: "hreflang-generator", name: "Hreflang Tag Generator", category: "Technical SEO",
    summary: "Create hreflang link tags from language-code and URL pairs.", fields: [{ name: "pairs", label: "One per line: language URL", type: "textarea", placeholder: "en-US https://example.com/\nfr https://example.com/fr/", required: true }, { name: "xdefault", label: "x-default URL", type: "url" }],
    howTo: ["List each language and URL.", "Add the full set to every language version."], faqs: [mkFaq("Must tags be reciprocal?", "Yes. Each page must list all alternates including itself.")], related: ["canonical-tag-generator"],
    run(i) { try { return { kind: "text", text: hreflangTags(lines(req(i, "pairs")).map((l) => { const [lang, url] = l.split(/\s+/); return { lang, url }; }), i.xdefault?.trim() || undefined), note: "Add to every language version." }; } catch (e) { throw new UserError((e as Error).message); } },
  },
  {
    slug: "canonical-tag-generator", name: "Canonical Tag Generator", category: "Technical SEO",
    summary: "Generate a canonical link tag for a URL.", fields: [URL_FIELD], howTo: ["Enter the preferred URL.", "Place the tag in the page head."], faqs: [mkFaq("Self-referencing canonicals?", "Recommended on indexable pages.")], related: ["hreflang-generator"],
    run(i) { try { return { kind: "text", text: canonicalTag(req(i, "url").replace(/^(?!https?:\/\/)/i, "https://")) }; } catch { throw new UserError("Enter a valid URL."); } },
  },
  {
    slug: "htaccess-redirect-generator", name: "htaccess Redirect Generator", category: "Technical SEO",
    summary: "Create Apache redirect rules, with optional HTTPS and www enforcement.",
    fields: [{ name: "rules", label: "One per line: /old /new [301|302]", type: "textarea", required: true }, { name: "https", label: "Force HTTPS", type: "select", options: ["no", "yes"] }, { name: "www", label: "www handling", type: "select", options: ["none", "add", "remove"] }],
    howTo: ["List redirects.", "Download and merge into your .htaccess.", "Test on staging first."], faqs: [mkFaq("Is it safe to paste directly?", "A bad .htaccess can take a site offline. Back up and test first.")], related: ["http-status-checker"],
    run(i) { try { const rules = lines(req(i, "rules")).map((l) => { const [from, to, st] = l.split(/\s+/); return { from, to, status: (Number(st) || 301) as 301 | 302 }; }); return { kind: "text", text: htaccessRedirects(rules, { forceHttps: i.https === "yes", wwwMode: (i.www || "none") as "add" | "remove" | "none" }), filename: ".htaccess", mime: "text/plain", note: "Review before deploying." }; } catch (e) { throw new UserError((e as Error).message); } },
  },
  {
    slug: "web-manifest-generator", name: "Web Manifest Generator", category: "Technical SEO",
    summary: "Create a manifest.webmanifest file.", fields: [{ name: "name", label: "App name", type: "text", required: true }, { name: "theme", label: "Theme color", type: "text", placeholder: "#0b1b3b" }, { name: "bg", label: "Background color", type: "text", placeholder: "#ffffff" }],
    howTo: ["Fill the fields.", "Download and link it with <link rel=\"manifest\">."], faqs: [mkFaq("Icons?", "Add icon entries for 192px and 512px PNGs before publishing.")], related: [],
    run(i) { try { return { kind: "text", text: webManifest({ name: req(i, "name"), themeColor: i.theme?.trim() || undefined, backgroundColor: i.bg?.trim() || undefined }), filename: "manifest.webmanifest", mime: "application/manifest+json" }; } catch (e) { throw new UserError((e as Error).message); } },
  },
  {
    slug: "url-encoder-decoder", name: "URL Encoder & Decoder", category: "Link & Status Utilities",
    summary: "Percent-encode or decode text for URLs.", fields: [{ name: "text", label: "Text", type: "textarea", required: true }, { name: "mode", label: "Mode", type: "select", options: ["encode", "decode"] }],
    howTo: ["Paste text.", "Choose encode or decode."], faqs: [mkFaq("encodeURIComponent?", "Yes. All reserved characters are encoded.")], related: ["url-parameter-analyzer"],
    run(i) { try { return { kind: "text", text: urlEncodeDecode(req(i, "text"), i.mode === "decode" ? "decode" : "encode") }; } catch { throw new UserError("Input is not valid percent-encoding."); } },
  },
  {
    slug: "url-parameter-analyzer", name: "URL Parameter Analyzer", category: "Link & Status Utilities",
    summary: "Split a URL into parts and flag tracking parameters.", fields: [URL_FIELD], howTo: ["Enter a URL with a query string."], faqs: [mkFaq("Why care about parameters?", "Tracking and sort parameters can create duplicate URLs; use canonicals or parameter rules.")], related: ["canonical-tag-generator"],
    run(i) { try { const r = analyzeUrlParams(req(i, "url").replace(/^(?!https?:\/\/)/i, "https://")); return { kind: "table", columns: ["Parameter", "Value", "Tracking?"], rows: r.params.map((p) => [p.key, p.value, p.isTracking ? "yes" : "no"]), csv: true, note: `Origin ${r.origin}, path ${r.path}` }; } catch { throw new UserError("Enter a valid URL."); } },
  },
  {
    slug: "link-extractor", name: "Internal & External Link Extractor", category: "Link & Status Utilities", network: true,
    summary: "List every link on a page with anchor text and rel attributes.", fields: [URL_FIELD],
    howTo: ["Enter a URL.", "Filter by type in the exported CSV."], faqs: [mkFaq("Does it check each link?", "No. Use the HTTP status checker for that.")], related: ["http-status-checker"],
    async run(i) {
      const r = await fetchPage(req(i, "url")); const p = parseHtml(r.body); const host = new URL(r.finalUrl).hostname;
      const rows: (string | number)[][] = [];
      for (const l of p.links) { try { const u = new URL(l.href, r.finalUrl); if (!/^https?:$/.test(u.protocol)) continue; rows.push([u.href, u.hostname === host ? "internal" : "external", l.text, l.rel || "follow"]); } catch { /* skip */ } }
      return { kind: "table", columns: ["URL", "Type", "Anchor text", "rel"], rows, csv: true };
    },
  },
  {
    slug: "url-list-cleaner", name: "URL List Deduplicator", category: "Link & Status Utilities",
    summary: "Remove duplicate and blank lines from a URL list.", fields: [{ name: "urls", label: "URLs", type: "textarea", required: true }], howTo: ["Paste URLs."], faqs: [mkFaq("Case sensitivity?", "Paths are case-sensitive, so duplicates are matched exactly.")], related: ["http-status-checker"],
    run(i) { const r = cleanKeywordList(lines(req(i, "urls")), { lowercase: false }); return { kind: "text", text: r.keywords.join("\n"), note: `${r.total} unique; ${r.duplicatesRemoved} duplicates removed.` }; },
  },

  // ---------- Site Audit & Crawling
  {
    slug: "site-crawler-audit", name: "Site Crawler & Technical Audit", category: "Site Audit & Crawling", network: true, heavy: true,
    summary: "Crawl up to 50 internal pages and report broken pages, duplicate or missing titles, missing meta descriptions, thin content, missing alt text, noindex pages and redirects.",
    fields: [URL_FIELD, { name: "maxPages", label: "Pages to crawl", type: "select", options: ["10", "25", "50"] }, { name: "robots", label: "Respect robots.txt", type: "select", options: ["yes", "no"] }],
    howTo: ["Enter a homepage or section URL.", "Choose how many pages to crawl.", "Review errors first, then warnings.", "Download the page table as CSV for a client report."],
    faqs: [
      mkFaq("How many pages can it crawl?", "Up to 50 per request, on the same host only. That keeps the run polite and under about a minute."),
      mkFaq("Does it check external links?", "No. It follows internal links only. External link checking is a separate tool because it requests third-party sites."),
      mkFaq("Does it respect robots.txt?", "Yes by default. Set it to 'no' only on sites you own."),
    ],
    related: ["broken-link-checker", "website-seo-checker", "xml-sitemap-validator"],
    async run(i) {
      const r = await crawlSite(withScheme(req(i, "url")), { maxPages: Number(i.maxPages) || 10, respectRobots: i.robots !== "no" });
      const findings: Finding[] = [];
      const add = (id: string, title: string, severity: Finding["severity"], why: string, extra: Partial<Finding> = {}) => { findings.push({ id, title, severity, why, ...extra }); };

      const failed = r.pages.filter((p) => p.error || p.status === 0 || p.status >= 400);
      if (failed.length) add("broken-pages", "Pages that failed to load", "error", "A page that returns an error cannot rank and wastes crawl budget.", { detected: `${failed.length} of ${r.pages.length} crawled`, element: list(failed.map((p) => `${p.status || "error"} ${p.url}`)), fix: "Fix the response or redirect the URL to a working page." });
      else add("broken-pages", "All crawled pages returned a success status", "pass", "No 4xx/5xx responses were found.");

      const titles = new Map<string, string[]>();
      for (const p of r.pages) if (p.title) titles.set(p.title, [...(titles.get(p.title) ?? []), p.url]);
      const dup = [...titles.entries()].filter(([, urls]) => urls.length > 1);
      if (dup.length) add("duplicate-titles", "Duplicate title tags", "warning", "Duplicate titles make it harder to tell pages apart in search results.", { detected: `${dup.length} duplicated title(s)`, element: list(dup.map(([t, u]) => `"${t}" → ${u.join(", ")}`), 3), fix: "Give every indexable page a unique, descriptive title." });
      const noTitle = r.pages.filter((p) => !p.title);
      if (noTitle.length) add("missing-titles", "Pages without a title tag", "error", "A missing title is a lost headline in search results.", { detected: `${noTitle.length} page(s)`, element: list(noTitle.map((p) => p.url)), fix: "Add one unique <title> per page." });
      else add("titles-present", "Every crawled page has a title", "pass", "Good baseline for the SERP snippet.");

      const noDesc = r.pages.filter((p) => !p.description);
      if (noDesc.length) add("missing-descriptions", "Pages without a meta description", "warning", "Google writes its own snippet from page copy, which you cannot control.", { detected: `${noDesc.length} page(s)`, element: list(noDesc.map((p) => p.url)), fix: "Add a unique 70-160 character description per page." });
      else add("descriptions-present", "Every crawled page has a meta description", "pass", "Snippets are under your control.");

      const noH1 = r.pages.filter((p) => p.h1Count === 0);
      const multiH1 = r.pages.filter((p) => p.h1Count > 1);
      if (noH1.length) add("missing-h1", "Pages without an H1", "warning", "The H1 states the page topic.", { detected: `${noH1.length} page(s)`, element: list(noH1.map((p) => p.url)), fix: "Add one descriptive H1 per page." });
      if (multiH1.length) add("multiple-h1", "Pages with more than one H1", "info", "Allowed in HTML5, but one clear H1 keeps the outline focused.", { detected: `${multiH1.length} page(s)`, element: list(multiH1.map((p) => p.url)) });

      const thin = r.pages.filter((p) => p.words < 300 && p.status === 200);
      if (thin.length) add("thin-content", "Thin pages (under 300 words)", "info", "Short pages often do not fully answer a query. Length alone is not a ranking factor.", { detected: `${thin.length} page(s)`, element: list(thin.map((p) => `${p.words}w ${p.url}`)) });

      const missingAlt = r.pages.reduce((n, p) => n + p.missingAlt, 0);
      const imageTotal = r.pages.reduce((n, p) => n + p.images, 0);
      if (missingAlt) add("missing-alt", "Images missing alt text", "warning", "Alt text supports accessibility and image search.", { detected: `${missingAlt} of ${imageTotal} images`, element: list(r.pages.filter((p) => p.missingAlt).map((p) => `${p.missingAlt} on ${p.url}`)), fix: "Add descriptive alt text; use alt=\"\" for decorative images." });
      else if (imageTotal) add("missing-alt", "All images have alt attributes", "pass", `${imageTotal} images checked`);

      const noindex = r.pages.filter((p) => p.noindex);
      if (noindex.length) add("noindex", "Pages set to noindex", "warning", "These pages are excluded from search results.", { detected: `${noindex.length} page(s)`, element: list(noindex.map((p) => p.url)), fix: "Remove noindex from pages that should rank." });

      const redirected = r.pages.filter((p) => p.redirects > 0);
      if (redirected.length) add("redirects", "Crawled URLs that redirect", "info", "Internal links should point at the final destination to save crawl budget.", { detected: `${redirected.length} page(s)`, element: list(redirected.map((p) => `${p.redirects} hop(s) ${p.url}`)), fix: "Update internal links to the final URL." });

      if (r.blockedByRobots) add("robots-blocked", "URLs blocked by robots.txt", "info", `robots.txt disallowed ${r.blockedByRobots} discovered URL(s), so they were not crawled.`);
      if (r.limitHit) add("crawl-limit", "Page limit reached", "info", "The crawl stopped at the page cap, so this report is partial.", { fix: "Raise the page limit or crawl a section at a time." });
      add("external-links", "External links", "unverified", "External links were not requested by this crawl. Use the broken link checker or HTTP status checker for those.", { detected: `${r.pages.reduce((n, p) => n + p.external, 0)} external link(s) seen` });

      return {
        kind: "table", columns: ["URL", "Status", "Title", "Words", "H1", "Missing alt", "Noindex", "Redirects"],
        rows: r.pages.map((p) => [p.url, p.error ? "error" : p.status, p.title ?? "", p.words, p.h1 ?? "", p.missingAlt, p.noindex ? "yes" : "no", p.redirects]),
        csv: true, findings, summary: summarize(findings),
        note: `Crawled ${r.pages.length} page(s) on ${r.host} in ${(r.elapsedMs / 1000).toFixed(1)}s. Internal links only; external URLs are not fetched.`,
      };
    },
  },
  {
    slug: "broken-link-checker", name: "Broken Link Checker", category: "Site Audit & Crawling", network: true, heavy: true,
    summary: "Check up to 100 internal and external links found on a page and see their status codes and errors.",
    fields: [URL_FIELD, { name: "limit", label: "Links to check", type: "select", options: ["25", "50", "100"] }, { name: "external", label: "Include external links", type: "select", options: ["yes", "no"] }],
    howTo: ["Enter the page that contains the links.", "Choose how many links to test.", "Fix every 4xx/5xx response first.", "Export the results as CSV."],
    faqs: [
      mkFaq("What counts as broken?", "Any 4xx/5xx response, DNS failure, TLS failure, timeout or blocked private address. A redirect that ends in 200 is reported as a redirect, not broken."),
      mkFaq("Is this a full site crawl?", "No. It checks the links on one page. Use the site crawler for multiple pages."),
      mkFaq("Why are some links skipped?", "Only http(s) links are tested; mailto:, tel: and javascript: links are ignored."),
    ],
    related: ["site-crawler-audit", "http-status-checker", "link-extractor"],
    async run(i) {
      const page = await safeFetch(req(i, "url"), { maxBytes: 2_000_000 });
      const p = parseHtml(page.body);
      const host = new URL(page.finalUrl).hostname;
      const targets = new Map<string, { type: string; anchor: string }>();
      for (const l of p.links) {
        try {
          const u = new URL(l.href, page.finalUrl);
          if (!/^https?:$/.test(u.protocol)) continue;
          const internal = u.hostname === host;
          if (!internal && i.external === "no") continue;
          u.hash = "";
          if (!targets.has(u.href)) targets.set(u.href, { type: internal ? "internal" : "external", anchor: l.text });
        } catch { /* invalid link */ }
      }
      const limit = Math.min(100, Math.max(1, Number(i.limit) || 25));
      const queue = [...targets.entries()].slice(0, limit);
      if (!queue.length) return { kind: "keyvalue", items: [["Links found", 0]], note: "No http(s) links matched your filter on this page." };

      const rows: (string | number)[][] = [];
      for (let k = 0; k < queue.length; k += 5) {
        const batch = queue.slice(k, k + 5);
        const res = await Promise.all(batch.map(async ([url, meta]): Promise<(string | number)[]> => {
          try {
            const r = await safeFetch(url, { method: "GET", maxBytes: 20_000, timeoutMs: 8_000 });
            const broken = r.status >= 400;
            return [url, r.status, meta.type, meta.anchor || "", broken ? "broken" : r.hops.length > 1 ? "redirect" : "ok", r.finalUrl === url ? "" : r.finalUrl];
          } catch (e) {
            return [url, "error", meta.type, meta.anchor || "", "broken", (e as Error).message];
          }
        }));
        rows.push(...res);
      }
      const broken = rows.filter((r) => r[4] === "broken").length;
      const redirects = rows.filter((r) => r[4] === "redirect").length;
      return { kind: "table", columns: ["URL", "Status", "Type", "Anchor", "Result", "Final URL"], rows, csv: true, note: `Checked ${rows.length} link(s): ${broken} broken, ${redirects} redirecting. Errors include DNS/TLS failures and blocked addresses.` };
    },
  },

  // ---------- Domain & Security
  {
    slug: "dns-lookup", name: "DNS Record Lookup", category: "Domain & Security", network: true,
    summary: "Look up A, AAAA, CNAME, MX, TXT, NS and SOA records for a domain, with TTL where the resolver provides it.",
    fields: [{ name: "domain", label: "Domain", type: "text", placeholder: "example.com", required: true }, { name: "type", label: "Record type", type: "select", options: [...DNS_TYPES, "ALL"] }],
    howTo: ["Enter a domain name.", "Pick a record type, or ALL.", "Copy the table or export it as CSV."],
    faqs: [
      mkFaq("Which resolver is used?", "The server's configured resolver. Results can differ slightly from another network or CDN edge."),
      mkFaq("Does this replace a full DNS audit?", "No. It shows public records for one domain; it does not test DNSSEC, propagation across resolvers or mail server behaviour."),
      mkFaq("Are internal hostnames allowed?", "No. Internal names and private IPs are blocked so the tool cannot be used to probe a network."),
    ],
    related: ["domain-age-checker", "ssl-certificate-checker"],
    async run(i) {
      const { hostname } = parseTargetUrl(withScheme(req(i, "domain")));
      if (!isDomainInput(hostname)) throw new UserError("Enter a domain name such as example.com.");
      const type = (i.type || "A").toUpperCase();
      const records = await lookupRecords(hostname, type);
      return {
        kind: "table", columns: ["Type", "Value", "TTL (s)"],
        rows: records.map((r) => [r.type, r.value, r.ttl ?? ""]), csv: true,
        note: records.length ? `${records.length} record(s) for ${hostname}.` : `No ${type === "ALL" ? "" : type + " "}records were returned for ${hostname}.`,
      };
    },
  },
  {
    slug: "ssl-certificate-checker", name: "SSL Certificate Checker", category: "Domain & Security", network: true,
    summary: "Read a site's TLS certificate: issuer, expiry, SANs, protocol, cipher and whether the chain is trusted.",
    fields: [URL_FIELD, { name: "port", label: "Port", type: "select", options: ["443", "8443"] }],
    howTo: ["Enter the site URL.", "Check the chain, expiry and protocol.", "Renew early and enable TLS 1.2+."],
    faqs: [
      mkFaq("Is the connection trusted?", "The tool first performs a normal verified handshake. If that fails, it reconnects without verification only to read the certificate, and reports the failure."),
      mkFaq("Does it check mixed content?", "No. Use the security headers grader and your browser console for page-level issues."),
      mkFaq("Why only ports 443 and 8443?", "Other ports are blocked so the tool cannot probe internal services."),
    ],
    related: ["security-headers-grader", "domain-age-checker", "website-seo-checker"],
    async run(i) {
      const c = await inspectCertificate(req(i, "url"), Number(i.port) || 443);
      const findings: Finding[] = [];
      if (!c.trusted) findings.push({ id: "trust", title: "Certificate chain is not trusted", severity: "error", detected: c.trustError ?? "verification failed", element: `${c.host}:${c.port}`, why: "Browsers warn users and may block the page when the certificate cannot be verified.", fix: "Install a valid certificate from a trusted CA and serve the full chain." });
      else findings.push({ id: "trust", title: "Certificate chain is trusted", severity: "pass", why: "The certificate verified against the system CA store." });

      if (c.daysRemaining < 0) findings.push({ id: "expiry", title: "Certificate has expired", severity: "error", detected: c.validTo, why: "Expired certificates break HTTPS and show a browser warning.", fix: "Renew the certificate now." });
      else if (c.daysRemaining < 14) findings.push({ id: "expiry", title: "Certificate expires very soon", severity: "error", detected: `${c.daysRemaining} day(s) left`, why: "Expiry causes an immediate outage for HTTPS visitors.", fix: "Renew and deploy now." });
      else if (c.daysRemaining < 30) findings.push({ id: "expiry", title: "Certificate expires within 30 days", severity: "warning", detected: `${c.daysRemaining} day(s) left`, why: "Manual renewals get missed; automate them.", fix: "Renew or confirm auto-renewal is working." });
      else findings.push({ id: "expiry", title: "Certificate is valid", severity: "pass", detected: `${c.daysRemaining} day(s) left`, why: "No immediate expiry risk." });

      if (c.protocol && /TLSv1(\.[01])?$/.test(c.protocol)) findings.push({ id: "protocol", title: "Outdated TLS protocol", severity: "warning", detected: c.protocol, why: "TLS 1.0/1.1 are deprecated and fail modern compliance checks.", fix: "Enable TLS 1.2 and TLS 1.3 only." });
      else if (c.protocol) findings.push({ id: "protocol", title: "Modern TLS protocol", severity: "pass", detected: c.protocol, why: "TLS 1.2+ is expected." });

      return {
        kind: "findings", summary: summarize(findings), findings,
        meta: {
          Host: `${c.host}:${c.port}`, Subject: c.subject || "(none)", Issuer: c.issuer || "(unknown)",
          "Valid from": c.validFrom, "Valid until": c.validTo, "Days remaining": String(c.daysRemaining),
          Protocol: c.protocol ?? "unknown", Cipher: c.cipher ?? "unknown", ALPN: c.alpn ?? "-",
          SANs: c.san.slice(0, 8).join(", ") + (c.san.length > 8 ? ` … (+${c.san.length - 8})` : ""),
          Serial: c.serial, "SHA-256": c.fingerprint,
        },
      };
    },
  },
  {
    slug: "domain-age-checker", name: "Domain Age & RDAP Lookup", category: "Domain & Security", network: true,
    summary: "Get a domain's registration date, age, expiry, registrar and nameservers from public RDAP registry data. No API key.",
    fields: [{ name: "domain", label: "Domain", type: "text", placeholder: "example.com", required: true }],
    howTo: ["Enter a domain name.", "Read the registration and expiry dates.", "Use it for due diligence, not as a ranking metric."],
    faqs: [
      mkFaq("Is domain age a ranking factor?", "Not directly, and Google has said age alone is not a factor. It is useful context for trust and history."),
      mkFaq("Where does the data come from?", "RDAP, the structured successor to WHOIS, served by the domain's registry. Some registries redact fields for privacy."),
      mkFaq("Why is the registrar missing?", "Privacy services and some TLDs omit or redact entity data in RDAP."),
    ],
    related: ["dns-lookup", "ssl-certificate-checker"],
    async run(i) {
      const d = await rdapLookup(req(i, "domain"));
      const years = d.ageDays === null ? null : Math.floor(d.ageDays / 365);
      return {
        kind: "keyvalue",
        items: [
          ["Domain", d.domain],
          ["Registrar", d.registrar ?? "(not published)"],
          ["Registered", d.registered ? d.registered.slice(0, 10) : "(not published)"],
          ["Domain age", d.ageDays === null ? "(unknown)" : `${years} year(s), ${d.ageDays % 365} day(s)`],
          ["Expires", d.expires ? d.expires.slice(0, 10) : "(not published)"],
          ["Last updated", d.updated ? d.updated.slice(0, 10) : "(not published)"],
          ["Status", d.statuses.join(", ") || "(none listed)"],
          ["Nameservers", d.nameservers.join(", ") || "(none listed)"],
        ],
        note: "Source: public RDAP registry data. Privacy services may redact registrar and dates.",
      };
    },
  },
  {
    slug: "security-headers-grader", name: "Security Headers Grader", category: "Domain & Security", network: true,
    summary: "Grade a page from A to F on eight security headers, with the value found and a fix for each missing one.",
    fields: [URL_FIELD],
    howTo: ["Enter a page URL.", "Read the grade and the per-header result.", "Add the missing headers at your server or CDN."],
    faqs: [
      mkFaq("Do security headers affect SEO?", "Only indirectly: HTTPS and a trustworthy site reduce risk and browser warnings. They are not a direct ranking factor."),
      mkFaq("Why is my CDN header not detected?", "The header must be present on the HTML response itself, after redirects. Check the final URL in the result."),
    ],
    related: ["ssl-certificate-checker", "http-header-analyzer"],
    async run(i) {
      const r = await safeFetch(req(i, "url"), { maxBytes: 50_000 });
      const g = gradeSecurityHeaders(r.headers);
      const findings: Finding[] = g.checks.map((c) => ({
        id: c.name, title: `${c.name} ${c.present ? "is set" : "is missing"}`,
        severity: c.present ? "pass" : c.weight >= 15 ? "error" : "warning",
        detected: c.value, why: c.why, fix: c.present ? undefined : c.fix,
      }));
      return { kind: "findings", summary: summarize(findings), findings, meta: { Grade: g.grade, Score: `${g.score}/${g.max}`, "Final URL": r.finalUrl } };
    },
  },

  // ---------- Content / technical additions
  {
    slug: "open-graph-preview", name: "Open Graph & Social Preview Audit", category: "Content Tools", network: true,
    summary: "Check the social tags on a page, see which are missing and get a corrected, copy-ready head snippet.",
    fields: [URL_FIELD],
    howTo: ["Enter the page URL.", "See which social tags exist.", "Copy the generated snippet into the page head."],
    faqs: [
      mkFaq("How do social platforms pick the image?", "They prefer og:image (or twitter:image) and usually need an absolute URL, at least 1200x630 for a large card."),
      mkFaq("Does this render the preview?", "No. It audits the tags and generates correct markup; it does not fetch or render the image."),
    ],
    related: ["meta-tag-generator", "website-seo-checker", "serp-snippet-preview"],
    async run(i) {
      const r = await safeFetch(req(i, "url"));
      const p = parseHtml(r.body);
      const found: [string, string][] = [
        ["og:title", p.og["og:title"] ?? ""], ["og:description", p.og["og:description"] ?? ""],
        ["og:image", p.og["og:image"] ?? ""], ["og:url", p.og["og:url"] ?? ""], ["og:type", p.og["og:type"] ?? ""],
        ["twitter:card", p.twitter["twitter:card"] ?? ""], ["twitter:title", p.twitter["twitter:title"] ?? ""], ["twitter:image", p.twitter["twitter:image"] ?? ""],
      ];
      const missing = found.filter(([, v]) => !v).map(([k]) => k);
      const snippet = socialPreviewTags({
        title: p.og["og:title"] || p.title,
        description: p.og["og:description"] || p.metaDescription,
        url: p.og["og:url"] || r.finalUrl,
        image: p.og["og:image"] || p.twitter["twitter:image"],
      });
      return { kind: "text", text: snippet, note: `${found.length - missing.length} of ${found.length} tags found.${missing.length ? ` Missing: ${missing.join(", ")}.` : ""} Page title: ${p.title ?? "(none)"}.` };
    },
  },
  {
    slug: "utm-campaign-builder", name: "UTM Campaign URL Builder", category: "Link & Status Utilities",
    summary: "Build a clean, lowercase UTM-tagged URL for email, ads and social, with warnings for missing values.",
    fields: [
      { name: "url", label: "Destination URL", type: "url", placeholder: "https://example.com/pricing", required: true },
      { name: "source", label: "Campaign source (utm_source)", type: "text", placeholder: "newsletter", required: true },
      { name: "medium", label: "Campaign medium (utm_medium)", type: "text", placeholder: "email", required: true },
      { name: "campaign", label: "Campaign name (utm_campaign)", type: "text", placeholder: "spring_launch", required: true },
      { name: "term", label: "Term (utm_term, optional)", type: "text" },
      { name: "content", label: "Content (utm_content, optional)", type: "text" },
    ],
    howTo: ["Paste the destination URL.", "Fill source, medium and campaign.", "Copy the tagged URL."],
    faqs: [
      mkFaq("Should UTM values be lowercase?", "Yes. Analytics tools treat 'Email' and 'email' as different channels, which fragments reporting."),
      mkFaq("Do UTMs affect SEO?", "Not directly, but tagged internal links create duplicate URLs. Never tag internal navigation; use them for campaigns only."),
    ],
    related: ["url-parameter-analyzer", "url-encoder-decoder"],
    run(i) {
      const u = utmUrl({ url: req(i, "url"), source: req(i, "source"), medium: req(i, "medium"), campaign: req(i, "campaign"), term: i.term, content: i.content });
      return { kind: "text", text: u.url, note: [u.warnings.join(" "), `Parameters: ${u.params.map(([k, v]) => `${k}=${v}`).join(", ")}`].filter(Boolean).join("\n") };
    },
  },
  {
    slug: "meta-tag-generator", name: "Meta Tag & Open Graph Generator", category: "Technical SEO",
    summary: "Generate a complete, escaped head block: title, description, robots, canonical, Open Graph and Twitter card.",
    fields: [
      { name: "title", label: "Page title", type: "text", required: true, placeholder: "Blue Widgets: Buying Guide" },
      { name: "description", label: "Meta description", type: "textarea", placeholder: "A concise, specific summary of the page." },
      { name: "url", label: "Canonical URL", type: "url", placeholder: "https://example.com/blue-widgets" },
      { name: "image", label: "Social image URL", type: "url", placeholder: "https://example.com/social.png" },
      { name: "siteName", label: "Site name", type: "text", placeholder: "Example Store" },
      { name: "twitter", label: "X/Twitter handle", type: "text", placeholder: "@example" },
      { name: "type", label: "Open Graph type", type: "select", options: ["website", "article", "product", "profile"] },
      { name: "robots", label: "Robots", type: "select", options: ["index,follow", "noindex,nofollow"] },
    ],
    howTo: ["Fill the title and description.", "Add the canonical and social image URLs.", "Copy the block into the page head."],
    faqs: [
      mkFaq("Where does this go?", "Inside the <head> of the page, replacing any existing title, description, canonical or social tags for that page."),
      mkFaq("Why escape the values?", "Quotes and angle brackets in a title would otherwise break the HTML and could inject markup."),
    ],
    related: ["open-graph-preview", "serp-snippet-preview", "canonical-tag-generator"],
    run(i) {
      const text = metaTags({ title: req(i, "title"), description: i.description, url: i.url, image: i.image, siteName: i.siteName, twitterHandle: i.twitter, type: i.type, robots: i.robots });
      return { kind: "text", text, filename: "meta-tags.html", mime: "text/html", note: "Paste inside <head>. Keep descriptions roughly 70-160 characters and titles under about 60." };
    },
  },
  {
    slug: "google-autocomplete-keywords", name: "Google Autocomplete Keyword Miner", category: "Keyword Tools", network: true,
    summary: "Pull real suggestions from Google Autocomplete for up to five seed keywords. No API key, no search volume.",
    fields: [{ name: "seeds", label: "Seed keywords (one per line, max 5)", type: "textarea", required: true, placeholder: "seo tools\nrobots txt" }, { name: "region", label: "Region", type: "select", options: ["us", "uk", "in", "ca", "au", "de"] }],
    howTo: ["Enter up to five seed keywords.", "Choose a region.", "Export the suggestions and group them with the clustering tool."],
    faqs: [
      mkFaq("Where do the suggestions come from?", "Google's public autocomplete endpoint, the data behind the search box dropdown. It reflects real typed queries, not our guesses."),
      mkFaq("Why is there no search volume?", "Volume and difficulty need a licensed keyword provider. Suggestions prove a query is typed; they do not quantify it."),
      mkFaq("Why might it return nothing?", "The endpoint can rate-limit or return no suggestions for unusual seeds. Try again later or rephrase."),
    ],
    related: ["keyword-suggestion-generator", "keyword-clustering-tool", "search-intent-classifier"],
    async run(i) {
      const seeds = lines(req(i, "seeds")).slice(0, 5);
      const region = (i.region || "us").replace(/[^a-z]/g, "");
      const rows: (string | number)[][] = [];
      for (const seed of seeds) {
        try {
          const url = `https://suggestqueries.google.com/complete/search?client=firefox&hl=en&gl=${region}&q=${encodeURIComponent(seed)}`;
          const r = await safeFetch(url, { maxBytes: 200_000, timeoutMs: 8_000 });
          if (r.status !== 200) { rows.push([seed, "(request failed)", `HTTP ${r.status}`]); continue; }
          const parsed = JSON.parse(r.body) as unknown;
          const suggestions = Array.isArray(parsed) && Array.isArray((parsed as unknown[])[1]) ? ((parsed as unknown[])[1] as unknown[]) : [];
          if (!suggestions.length) { rows.push([seed, "(no suggestions)", ""]); continue; }
          for (const s of suggestions) if (typeof s === "string" && s.trim()) rows.push([seed, s.trim(), ""]);
        } catch (e) { rows.push([seed, "(request failed)", (e as Error).message]); }
      }
      return { kind: "table", columns: ["Seed", "Suggestion", "Note"], rows, csv: true, note: "Suggestions come from Google's public autocomplete endpoint. They show that people type these queries; they do not include volume or difficulty." };
    },
  },
];

export const bySlug = new Map(TOOLS.map((t) => [t.slug, t]));
export { toCsv, USER_AGENT };
