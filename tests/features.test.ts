import { test } from "node:test";
import assert from "node:assert/strict";
import { gradeSecurityHeaders } from "../src/lib/network/headers.ts";
import { normalizeCrawlUrl } from "../src/lib/network/crawler.ts";
import { isDomainInput } from "../src/lib/network/dns.ts";
import { utmUrl, metaTags } from "../src/lib/generators/generators.ts";
import { scoreHealth } from "../src/lib/seo/health.ts";
import { normalizePsi, psiApiUrl } from "../src/lib/network/pagespeed.ts";
import { parseHtml } from "../src/lib/html/parse.ts";
import { TOOLS, CATEGORIES } from "../src/tools/registry.ts";

test("security header grading is weighted and explains every check", () => {
  const empty = gradeSecurityHeaders({});
  assert.equal(empty.grade, "F");
  assert.equal(empty.score, 0);
  assert.equal(empty.checks.length, 8);
  assert.ok(empty.checks.every((c) => c.fix.length > 0));

  const full = gradeSecurityHeaders({
    "strict-transport-security": "max-age=31536000",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "geolocation=()",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
  });
  assert.equal(full.grade, "A");
  assert.equal(full.score, full.max);
  // CSP frame-ancestors counts as clickjacking protection even without X-Frame-Options
  assert.equal(full.checks.find((c) => c.name === "X-Frame-Options")!.present, true);
});

test("UTM builder normalises values and preserves existing query params", () => {
  const u = utmUrl({ url: "https://example.com/p?x=1", source: "Email Newsletter", medium: "email", campaign: "Spring Launch" });
  const p = new URL(u.url).searchParams;
  assert.equal(p.get("x"), "1");
  assert.equal(p.get("utm_source"), "email_newsletter");
  assert.equal(p.get("utm_campaign"), "spring_launch");
  assert.equal(u.params.length, 3);
  assert.equal(u.warnings.length, 0);

  const warn = utmUrl({ url: "https://example.com", source: "", medium: "email", campaign: "x" });
  assert.ok(warn.warnings.some((w) => w.includes("utm_source")));
  // addresses without a scheme are accepted
  assert.match(utmUrl({ url: "example.com", source: "a", medium: "b", campaign: "c" }).url, /^https:\/\/example\.com\//);
});

test("meta tag generator escapes input and builds canonical + social tags", () => {
  const html = metaTags({ title: 'A "quoted" <title>', description: "Desc & more", url: "https://example.com/p", image: "/og.png", siteName: "Shop", twitterHandle: "shop" });
  assert.match(html, /&quot;quoted&quot; &lt;title&gt;/);
  assert.match(html, /property="og:image" content="https:\/\/example\.com\/og\.png"/);
  assert.match(html, /name="twitter:site" content="@shop"/);
  assert.match(html, /rel="canonical" href="https:\/\/example\.com\/p"/);
  assert.ok(!html.includes('<title>A "quoted"'));
});

test("crawler URL normalisation drops fragments, tracking params and trailing slashes", () => {
  assert.equal(normalizeCrawlUrl("/about#team", "https://Example.com/"), "https://example.com/about");
  assert.equal(normalizeCrawlUrl("?utm_source=x&id=2", "https://example.com/a/"), "https://example.com/a?id=2");
  assert.equal(normalizeCrawlUrl("mailto:a@b.c", "https://example.com"), null);
  assert.equal(normalizeCrawlUrl("javascript:void(0)", "https://example.com"), null);
  assert.equal(normalizeCrawlUrl("/", "https://example.com"), "https://example.com/");
});

test("domain input validation rejects bare labels and bad hyphens", () => {
  assert.equal(isDomainInput("example.com"), true);
  assert.equal(isDomainInput("sub.example.co.uk"), true);
  assert.equal(isDomainInput("localhost"), false);
  assert.equal(isDomainInput("-bad.com"), false);
  assert.equal(isDomainInput("example"), false);
});

test("site health scoring: weights hit 100, good site grades A, broken site grades F", () => {
  const GOOD_HEADERS = {
    "strict-transport-security": "max-age=31536000",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "geolocation=()",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
  };
  const goodPage = parseHtml(`<html lang="en"><head><title>Example domain page title for testing</title>
<meta name="description" content="${"A".repeat(120)}"><link rel="canonical" href="https://example.com/">
<meta name="viewport" content="width=device-width, initial-scale=1"></head><body><h1>Example</h1></body></html>`);

  const goodPsi = {
    finalUrl: "https://example.com/", strategy: "mobile" as const, performance: 96,
    field: {
      scope: "page" as const, overall: "good" as const,
      metrics: [
        { id: "lcp", label: "LCP", display: "1.8 s", rating: "good" as const, source: "field" as const },
        { id: "cls", label: "CLS", display: "0.02", rating: "good" as const, source: "field" as const },
        { id: "inp", label: "INP", display: "120 ms", rating: "good" as const, source: "field" as const },
      ],
    },
    lab: [], opportunities: [], fetchMs: 1200,
  };

  const goodInput = {
    finalUrl: "https://example.com/", status: 200, headers: GOOD_HEADERS, page: goodPage,
    tls: { trusted: true, daysRemaining: 90, protocol: "TLSv1.3" },
    dns: { records: 6 }, robots: { status: 200, disallowsAll: false },
    sitemap: { status: 200, entries: 42, type: "urlset" },
    crawl: { pages: 10, broken: 0, duplicateTitles: 0, noindex: 0, missingAlt: 0 },
    pagespeed: goodPsi,
  };
  const good = scoreHealth(goodInput);
  assert.equal(good.max, 100);
  assert.equal(good.score, 100);
  assert.equal(good.grade, "A");
  assert.equal(good.topFixes.length, 0);

  // A PageSpeed outage is "unverified", never a penalty.
  const noPsi = scoreHealth({ ...goodInput, pagespeed: null });
  assert.equal(noPsi.max, 100);
  assert.equal(noPsi.score, 100);
  assert.equal(noPsi.checks.filter((c) => c.status === "unverified").length, 2);

  const bad = scoreHealth({
    finalUrl: "http://example.com/", status: 500, headers: {},
    page: parseHtml("<html><body></body></html>"),
    tls: null, dns: null, robots: { status: 200, disallowsAll: true },
    sitemap: { status: 404, entries: 0, type: "unknown" },
    crawl: { pages: 3, broken: 2, duplicateTitles: 1, noindex: 1, missingAlt: 4 },
    pagespeed: null,
  });
  assert.ok(bad.score < 40, `score ${bad.score}`);
  assert.equal(bad.grade, "F");
  assert.ok(bad.topFixes.length > 0 && bad.topFixes.length <= 5);
  // Unverified TLS/DNS never subtract points
  assert.equal(bad.checks.find((c) => c.id === "tls")!.status, "unverified");
  assert.equal(bad.checks.find((c) => c.id === "lighthouse-performance")!.status, "unverified");
  // A missing sitemap is a warning, not a hard failure
  assert.equal(bad.checks.find((c) => c.id === "sitemap")!.status, "warning");
});

test("PageSpeed normalisation: lab, field, opportunities and honest failures", () => {
  const fixture = {
    lighthouseResult: {
      finalUrl: "https://example.com/",
      categories: { performance: { score: 0.42 } },
      audits: {
        "largest-contentful-paint": { score: 0.3, displayValue: "4.2 s" },
        "cumulative-layout-shift": { score: 0.98, displayValue: "0.01" },
        "total-blocking-time": { score: 0.6, displayValue: "310 ms" },
        "first-contentful-paint": { score: 0.7, displayValue: "2.1 s" },
        "server-response-time": { score: 0.95, displayValue: "0.1 s" },
        "unused-javascript": { score: 0.2, numericValue: 1200, title: "Reduce unused JavaScript", displayValue: "Potential savings of 1,200 ms", details: { type: "opportunity" } },
        "render-blocking-resources": { score: 0.4, numericValue: 800, title: "Eliminate render-blocking resources", displayValue: "Potential savings of 800 ms", details: { type: "opportunity" } },
      },
    },
    loadingExperience: {
      overall_category: "AVERAGE",
      metrics: {
        LARGEST_CONTENTFUL_PAINT_MS: { percentile: 3100, category: "AVERAGE" },
        CUMULATIVE_LAYOUT_SHIFT_SCORE: { percentile: 7, category: "FAST" },
        INTERACTION_TO_NEXT_PAINT: { percentile: 180, category: "FAST" },
      },
    },
  };

  const r = normalizePsi(fixture, "mobile", "https://example.com/");
  assert.equal(r.performance, 42);
  assert.equal(r.field!.overall, "needs-improvement");
  assert.equal(r.field!.metrics.find((m) => m.label === "CLS")!.display, "0.07");
  assert.equal(r.lab.find((m) => m.label === "LCP")!.rating, "poor");
  assert.equal(r.opportunities[0].savingsMs, 1200);
  assert.equal(r.opportunities.length, 2);

  // No CrUX data, no lab audits: still a valid report, nothing invented.
  const bare = normalizePsi({ lighthouseResult: { categories: { performance: { score: 0.95 } }, audits: {} } }, "desktop", "https://x.test/");
  assert.equal(bare.performance, 95);
  assert.equal(bare.field, null);
  assert.equal(bare.lab.length, 0);

  assert.throws(() => normalizePsi({ error: { message: "Quota exceeded" } }, "mobile", "https://x.test/"), /Quota exceeded/);
});

test("PageSpeed request URL carries target, strategy and an optional key", () => {
  const plain = new URL(psiApiUrl("https://example.com/a?b=1", "desktop"));
  assert.equal(plain.origin + plain.pathname, "https://www.googleapis.com/pagespeedonline/v5/runPagespeed");
  assert.equal(plain.searchParams.get("url"), "https://example.com/a?b=1");
  assert.equal(plain.searchParams.get("strategy"), "desktop");
  assert.equal(plain.searchParams.get("category"), "performance");
  assert.equal(plain.searchParams.get("key"), null);

  const keyed = new URL(psiApiUrl("https://example.com", "mobile", "abc123"));
  assert.equal(keyed.searchParams.get("key"), "abc123");
});

test("registry: site health report is the first tool and is rate-limited as heavy", () => {
  assert.equal(TOOLS[0].slug, "site-health-report");
  assert.equal(TOOLS[0].heavy, true);
  assert.equal(TOOLS[0].network, true);
  assert.equal(TOOLS[0].fields.length, 1);

  const psi = TOOLS.find((t) => t.slug === "pagespeed-insights")!;
  assert.ok(psi, "pagespeed-insights tool exists");
  assert.equal(psi.heavy, true);
  assert.equal(psi.network, true);
  assert.deepEqual(psi.fields.find((f) => f.name === "strategy")!.options, ["mobile", "desktop"]);
});

test("registry: new paid-tier tools exist and every category is populated", () => {
  const added = [
    "site-crawler-audit", "broken-link-checker", "dns-lookup", "ssl-certificate-checker",
    "domain-age-checker", "security-headers-grader", "open-graph-preview",
    "utm-campaign-builder", "meta-tag-generator", "google-autocomplete-keywords",
  ];
  for (const slug of added) assert.ok(TOOLS.some((t) => t.slug === slug), slug);
  assert.equal(new Set(TOOLS.map((t) => t.slug)).size, TOOLS.length);
  for (const c of CATEGORIES) assert.ok(TOOLS.some((t) => t.category === c), c);
  assert.equal(TOOLS.find((t) => t.slug === "site-crawler-audit")!.heavy, true);
  assert.equal(TOOLS.find((t) => t.slug === "site-crawler-audit")!.network, true);
  assert.equal(TOOLS.find((t) => t.slug === "utm-campaign-builder")!.network, undefined);
});
