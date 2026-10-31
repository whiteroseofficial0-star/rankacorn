import { test } from "node:test";
import assert from "node:assert/strict";
import { parseHtml } from "../src/lib/html/parse.ts";
import { analyzePage, summarize } from "../src/lib/seo/analyze.ts";
import { parseRobots, isAllowed, generateRobots } from "../src/lib/seo/robots.ts";
import { parseSitemap, generateSitemap } from "../src/lib/seo/sitemap.ts";
import { toCsv, parseCsv } from "../src/lib/text/csv.ts";
import { countText, readability, keywordDensity, keywordFrequency, textSimilarity, slugify } from "../src/lib/text/analysis.ts";
import { cleanKeywordList, classifyIntent, clusterKeywords, questionKeywords } from "../src/lib/text/keywords.ts";
import { schemaMarkup, formatJsonLd, htaccessRedirects, hreflangTags, analyzeUrlParams, serpSnippet } from "../src/lib/generators/generators.ts";

const HTML = `<!doctype html><html lang="en"><head>
<title>Best Blue Widgets &amp; Gadgets for Home Offices</title>
<meta name="description" content="Compare the best blue widgets for your home office, with honest pricing notes and buying tips for every budget.">
<link rel="canonical" href="https://example.com/widgets">
<meta property="og:title" content="Widgets"><meta name="twitter:card" content="summary">
<meta name="viewport" content="width=device-width, initial-scale=1">
<script type="application/ld+json">{"@context":"https://schema.org","@type":"Article","headline":"x"}</script>
<script type="application/ld+json">{bad json</script>
</head><body>
<h1>Blue Widgets</h1><h3>Skipped</h3>
<p>Hello <a href="/about" rel="nofollow">About us</a> and <a href="https://other.com/x">Other</a> <a href="/img"><img src="a.png" alt="Logo"></a></p>
<img src="b.png"><img src="c.png" alt="">
<script>var x = "<h1>not real</h1>";</script>
</body></html>`;

test("parseHtml extracts core elements and ignores script contents", () => {
  const p = parseHtml(HTML);
  assert.equal(p.title, "Best Blue Widgets & Gadgets for Home Offices");
  assert.match(p.metaDescription ?? "", /^Compare the best/);
  assert.equal(p.canonical, "https://example.com/widgets");
  assert.equal(p.lang, "en");
  assert.deepEqual(p.headings.map((h) => h.level), [1, 3]);
  assert.equal(p.links.length, 3);
  assert.equal(p.links[0].rel, "nofollow");
  assert.equal(p.links[2].text, "Logo"); // falls back to img alt
  assert.deepEqual(p.images.map((i) => i.alt), ["Logo", null, ""]);
  assert.equal(p.jsonLd.length, 2);
  assert.ok(p.jsonLd[1].error);
  assert.equal(p.og["og:title"], "Widgets");
  assert.equal(p.twitter["twitter:card"], "summary");
});

test("analyzePage reports detected problems and marks unverifiable items", () => {
  const p = parseHtml(HTML);
  const f = analyzePage(p, { finalUrl: "https://example.com/widgets", status: 200, headers: {}, redirectHops: 1 });
  const byId = (id: string) => f.find((x) => x.id === id)!;
  assert.equal(byId("img-alt").severity, "warning");
  assert.equal(byId("json-ld").severity, "error");
  assert.equal(byId("heading-skip").severity, "info");
  assert.equal(byId("canonical").severity, "pass");
  assert.equal(byId("open-graph").severity, "info");
  assert.equal(byId("broken-links").severity, "unverified");
  assert.equal(byId("core-web-vitals").severity, "unverified");
  assert.ok(summarize(f).error >= 1);
});

test("noindex via header is detected", () => {
  const f = analyzePage(parseHtml("<html><head><title>t</title></head><body></body></html>"), {
    finalUrl: "http://example.com/", status: 200, headers: { "x-robots-tag": "noindex" }, redirectHops: 1,
  });
  assert.equal(f.find((x) => x.id === "indexability")!.severity, "warning");
  assert.equal(f.find((x) => x.id === "https")!.severity, "error");
});

test("robots parsing and matching (longest match wins, wildcards, $)", () => {
  const r = parseRobots(`User-agent: *\nDisallow: /private/\nAllow: /private/public.html\nDisallow: /*.pdf$\nCrawl-delay: 5\n\nUser-agent: Googlebot\nDisallow: /nogoogle\nSitemap: https://example.com/sitemap.xml\nBogus: x`);
  assert.equal(r.sitemaps[0], "https://example.com/sitemap.xml");
  assert.ok(r.warnings.some((w) => w.includes("bogus")));
  assert.equal(r.groups[0].crawlDelay, 5);
  assert.equal(isAllowed(r, "RankacornBot", "/private/secret").allowed, false);
  assert.equal(isAllowed(r, "RankacornBot", "/private/public.html").allowed, true);
  assert.equal(isAllowed(r, "RankacornBot", "/files/a.pdf").allowed, false);
  assert.equal(isAllowed(r, "RankacornBot", "/files/a.pdf?x=1").allowed, true);
  assert.equal(isAllowed(r, "Googlebot", "/nogoogle/x").allowed, false);
  assert.equal(isAllowed(r, "Googlebot", "/private/x").allowed, true); // Googlebot group has no such rule
});

test("robots generator", () => {
  const t = generateRobots({ disallow: ["/admin/"], sitemaps: ["https://example.com/sitemap.xml"] });
  assert.equal(t, "User-agent: *\nDisallow: /admin/\n\nSitemap: https://example.com/sitemap.xml\n");
});

test("sitemap generate -> parse round trip, escaping, validation", () => {
  const xml = generateSitemap([{ loc: "https://example.com/a?x=1&y=2", lastmod: "2026-01-02", priority: 0.8 }, { loc: "https://example.com/b" }]);
  assert.match(xml, /&amp;y=2/);
  const p = parseSitemap(xml);
  assert.equal(p.type, "urlset");
  assert.equal(p.urls[0].loc, "https://example.com/a?x=1&y=2");
  assert.equal(p.errors.length, 0);
  const bad = parseSitemap(`<urlset><url><loc>notaurl</loc><priority>3</priority></url><url><loc>https://e.com/</loc></url><url><loc>https://e.com/</loc></url></urlset>`);
  assert.ok(bad.errors.length >= 1);
  assert.ok(bad.warnings.some((w) => w.includes("Duplicate")));
  assert.ok(bad.warnings.some((w) => w.includes("priority")));
  assert.equal(parseSitemap("<html/>").errors.length, 1);
  assert.equal(parseSitemap("<sitemapindex><sitemap><loc>https://e.com/s1.xml</loc></sitemap></sitemapindex>").type, "sitemapindex");
});

test("CSV: BOM, quoting, formula injection guard, round trip", () => {
  const csv = toCsv([["kw", "note"], ["a,b", 'say "hi"'], ["=HYPERLINK(1)", "-5"]]);
  assert.ok(csv.startsWith("﻿"));
  assert.match(csv, /"a,b","say ""hi"""/);
  assert.match(csv, /'=HYPERLINK\(1\),-5/);
  assert.deepEqual(parseCsv(csv)[1], ["a,b", 'say "hi"']);
  assert.deepEqual(parseCsv("a,b\r\n\r\nc,d\n"), [["a", "b"], ["c", "d"]]);
});

test("text counters, readability, density, similarity, slug", () => {
  const c = countText("One two three. Four five!\n\nSix.");
  assert.equal(c.words, 6); assert.equal(c.sentences, 3); assert.equal(c.paragraphs, 2);
  assert.ok(readability("The cat sat on the mat. It was a sunny day.").fleschReadingEase! > 80);
  assert.equal(readability("").fleschReadingEase, null);
  assert.equal(keywordDensity("blue widget blue widget red", "blue widget").occurrences, 2);
  assert.equal(keywordFrequency("seo tools help seo teams with seo", { top: 1 })[0].term, "seo");
  assert.equal(textSimilarity("the quick brown fox", "the quick brown fox").jaccardPercent, 100);
  assert.ok(textSimilarity("apples and oranges", "cars and trucks").cosinePercent < 50);
  assert.equal(slugify("Café & Crème: The 10 Best Tips!"), "cafe-and-creme-the-10-best-tips");
  assert.equal(slugify("The best way to cook", { removeStopWords: true }), "best-way-cook");
});

test("keyword tools", () => {
  const c = cleanKeywordList("SEO tools\nseo tools\n  Rank   tracker ,\n\n");
  assert.deepEqual(c.keywords, ["seo tools", "rank tracker"]);
  assert.equal(c.duplicatesRemoved, 1);
  assert.equal(classifyIntent("buy running shoes").intent, "transactional");
  assert.equal(classifyIntent("best seo tools vs ahrefs").intent, "commercial");
  assert.equal(classifyIntent("how to write a title").intent, "informational");
  assert.equal(classifyIntent("pizza near me").intent, "local");
  assert.ok(questionKeywords("seo").includes("what is seo"));
  const cl = clusterKeywords(["seo tools", "free seo tools", "seo audit", "email marketing", "email templates"]);
  assert.ok(cl.find((x) => x.label === "seo")!.keywords.length === 3);
  assert.equal(cl.flatMap((x) => x.keywords).length, 5);
});

test("generators", () => {
  const s = schemaMarkup("FAQPage", { faqs: [{ question: "Q?", answer: "A </script>" }] });
  assert.ok(!s.slice(40, -9).includes("</script>")); // cannot break out of the script tag
  const inner = s.replace(/^<script[^>]*>\n/, "").replace(/\n<\/script>$/, "");
  assert.equal(JSON.parse(inner).mainEntity[0].name, "Q?");
  assert.throws(() => schemaMarkup("Article", {}), /headline/);
  const j = formatJsonLd('{"@type":"Thing"}');
  assert.ok(j.ok && j.warnings.length === 1);
  assert.equal(formatJsonLd("{oops").ok, false);
  assert.match(htaccessRedirects([{ from: "/old", to: "/new" }], { forceHttps: true }), /Redirect 301 \/old \/new/);
  assert.throws(() => htaccessRedirects([{ from: "old", to: "/x" }]));
  assert.throws(() => hreflangTags([{ lang: "english", url: "https://e.com" }]));
  assert.match(hreflangTags([{ lang: "en-US", url: "https://e.com/" }], "https://e.com/"), /x-default/);
  const up = analyzeUrlParams("https://e.com/p?utm_source=x&id=3");
  assert.equal(up.hasTrackingParams, true);
  assert.equal(serpSnippet("t".repeat(70), "d", "https://e.com/a/b").titleTruncated, true);
});
