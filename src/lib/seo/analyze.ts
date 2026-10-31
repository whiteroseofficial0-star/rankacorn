import type { ParsedPage } from "../html/parse.ts";

export type Severity = "error" | "warning" | "info" | "pass" | "unverified";

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  element?: string; // affected element or URL
  detected?: string; // what was actually found
  why: string;
  fix?: string;
  example?: string;
}

export interface AnalyzeContext {
  finalUrl: string;
  status: number;
  headers: Record<string, string | string[] | undefined>;
  redirectHops: number;
}

const hdr = (h: AnalyzeContext["headers"], name: string): string | undefined => {
  const v = h[name.toLowerCase()];
  return Array.isArray(v) ? v.join(", ") : v;
};

export function analyzePage(p: ParsedPage, ctx: AnalyzeContext): Finding[] {
  const f: Finding[] = [];
  const url = new URL(ctx.finalUrl);

  // --- Status / HTTPS / redirects
  if (ctx.status >= 400) {
    f.push({ id: "http-status", title: "Page returned an error status", severity: "error", detected: String(ctx.status), element: ctx.finalUrl, why: "Search engines will not index pages that return 4xx/5xx responses.", fix: "Make the URL return 200 or redirect it to a working page." });
  } else {
    f.push({ id: "http-status", title: "Page returns a successful status", severity: "pass", detected: String(ctx.status), why: "A 200 response is required for indexing." });
  }
  if (url.protocol !== "https:") {
    f.push({ id: "https", title: "Page is not served over HTTPS", severity: "error", detected: url.protocol, why: "HTTPS is a lightweight ranking signal and browsers warn on HTTP pages.", fix: "Install a TLS certificate and 301-redirect all HTTP URLs to HTTPS." });
  } else f.push({ id: "https", title: "Served over HTTPS", severity: "pass", why: "Secure connection." });
  if (ctx.redirectHops > 1) {
    f.push({ id: "redirect-chain", title: "Redirect chain detected", severity: "warning", detected: `${ctx.redirectHops} redirects`, why: "Each hop slows crawling and can dilute signals.", fix: "Redirect the original URL straight to the final destination." });
  }

  // --- Title
  if (!p.title) {
    f.push({ id: "title", title: "Missing title tag", severity: "error", element: "<title>", why: "The title is the main headline shown in search results.", fix: "Add a unique, descriptive <title> of about 30-60 characters.", example: "<title>Primary Keyword - Brand Name</title>" });
  } else if (p.title.length < 30 || p.title.length > 60) {
    f.push({ id: "title", title: p.title.length < 30 ? "Title is short" : "Title may be truncated", severity: "warning", element: "<title>", detected: `${p.title.length} chars: ${p.title}`, why: "Titles over roughly 60 characters (about 580px) are often cut off; very short titles waste space.", fix: "Aim for roughly 30-60 characters (a guideline, not a Google rule)." });
  } else f.push({ id: "title", title: "Title length is within guideline", severity: "pass", detected: `${p.title.length} chars` , why: "Likely to display fully." });

  // --- Meta description
  if (p.metaDescription === null || p.metaDescription.trim() === "") {
    f.push({ id: "meta-description", title: "Missing meta description", severity: "warning", element: 'meta[name="description"]', why: "Google may use it as the snippet; without it, a snippet is generated from page text.", fix: "Write a unique summary of about 70-160 characters.", example: '<meta name="description" content="A concise summary that invites the click.">' });
  } else if (p.metaDescription.length < 70 || p.metaDescription.length > 160) {
    f.push({ id: "meta-description", title: "Meta description length outside guideline", severity: "info", detected: `${p.metaDescription.length} chars`, why: "Long descriptions are truncated; short ones may not be persuasive. Google can rewrite snippets regardless.", fix: "Aim for roughly 70-160 characters." });
  } else f.push({ id: "meta-description", title: "Meta description present", severity: "pass", detected: `${p.metaDescription.length} chars`, why: "Within guideline." });

  // --- Headings
  const h1s = p.headings.filter((h) => h.level === 1);
  if (h1s.length === 0) f.push({ id: "h1", title: "Missing H1", severity: "warning", why: "An H1 states the page topic to users and crawlers.", fix: "Add one descriptive <h1>.", example: "<h1>Primary topic of the page</h1>" });
  else if (h1s.length > 1) f.push({ id: "h1", title: "Multiple H1 headings", severity: "info", detected: `${h1s.length} H1s`, why: "HTML5 allows several, but one clear H1 keeps the page focused.", fix: "Consider using a single H1 and H2s for sections." });
  else f.push({ id: "h1", title: "Single H1 present", severity: "pass", detected: h1s[0].text, why: "Clear page topic." });
  for (let i = 1; i < p.headings.length; i++) {
    if (p.headings[i].level - p.headings[i - 1].level > 1) {
      f.push({ id: "heading-skip", title: "Heading level skipped", severity: "info", element: `<h${p.headings[i].level}> "${p.headings[i].text.slice(0, 50)}"`, detected: `h${p.headings[i - 1].level} → h${p.headings[i].level}`, why: "Skipped levels hurt outline clarity and accessibility.", fix: "Use consecutive heading levels." });
      break;
    }
  }

  // --- Images
  const missingAlt = p.images.filter((i) => i.alt === null);
  if (missingAlt.length) {
    f.push({ id: "img-alt", title: "Images missing alt attribute", severity: "warning", detected: `${missingAlt.length} of ${p.images.length}`, element: missingAlt.slice(0, 5).map((i) => i.src).join(", "), why: "Alt text supports accessibility and image search. Decorative images should use alt=\"\".", fix: "Add descriptive alt text.", example: '<img src="logo.png" alt="Company logo">' });
  } else if (p.images.length) f.push({ id: "img-alt", title: "All images have alt attributes", severity: "pass", detected: `${p.images.length} images`, why: "Good accessibility." });

  // --- Canonical
  if (p.canonical === null) f.push({ id: "canonical", title: "No canonical tag", severity: "info", why: "A canonical helps consolidate duplicate URLs.", fix: "Add a self-referencing canonical.", example: `<link rel="canonical" href="${ctx.finalUrl}">` });
  else {
    let abs: URL | null = null;
    try { abs = new URL(p.canonical, ctx.finalUrl); } catch { /* invalid */ }
    if (!abs) f.push({ id: "canonical", title: "Canonical URL is invalid", severity: "error", detected: p.canonical, why: "An invalid canonical is ignored.", fix: "Use an absolute, valid URL." });
    else if (!/^https?:\/\//i.test(p.canonical)) f.push({ id: "canonical", title: "Canonical is relative", severity: "warning", detected: p.canonical, why: "Absolute canonicals are recommended.", fix: `Use ${abs.href}` });
    else if (abs.href.replace(/\/$/, "") !== url.href.replace(/\/$/, "")) f.push({ id: "canonical", title: "Canonical points to a different URL", severity: "info", detected: abs.href, why: "This page asks search engines to index another URL. Fine if intended.", fix: "Verify this is deliberate." });
    else f.push({ id: "canonical", title: "Self-referencing canonical", severity: "pass", detected: abs.href, why: "Correctly set." });
  }

  // --- Indexability
  const xrobots = hdr(ctx.headers, "x-robots-tag") ?? "";
  const noindex = /noindex/i.test(p.robotsMeta ?? "") || /noindex/i.test(xrobots);
  f.push(noindex
    ? { id: "indexability", title: "Page is set to noindex", severity: "warning", detected: `meta: ${p.robotsMeta ?? "-"}; X-Robots-Tag: ${xrobots || "-"}`, why: "This page will be excluded from search results.", fix: "Remove noindex if the page should rank." }
    : { id: "indexability", title: "No noindex directive found", severity: "pass", why: "Page appears indexable. (robots.txt blocking is checked separately.)" });

  // --- Mobile / language / charset
  f.push(p.viewport ? { id: "viewport", title: "Viewport meta tag present", severity: "pass", detected: p.viewport, why: "Required for mobile-friendly rendering." } : { id: "viewport", title: "Missing viewport meta tag", severity: "warning", why: "Without it, mobile browsers render a desktop-sized page.", fix: "Add the viewport tag.", example: '<meta name="viewport" content="width=device-width, initial-scale=1">' });
  if (!p.lang) f.push({ id: "lang", title: "Missing html lang attribute", severity: "info", why: "Helps accessibility tools and language targeting.", fix: "Add lang to the html element.", example: '<html lang="en">' });

  // --- Social
  const missingOg = ["og:title", "og:description", "og:image", "og:url"].filter((k) => !p.og[k]);
  f.push(missingOg.length ? { id: "open-graph", title: "Open Graph tags incomplete", severity: "info", detected: `Missing: ${missingOg.join(", ")}`, why: "Controls link previews on social platforms.", fix: "Add the missing tags." } : { id: "open-graph", title: "Open Graph tags complete", severity: "pass", why: "Link previews configured." });
  f.push(p.twitter["twitter:card"] ? { id: "twitter-card", title: "Twitter/X card present", severity: "pass", detected: p.twitter["twitter:card"], why: "Link previews configured." } : { id: "twitter-card", title: "No Twitter/X card tags", severity: "info", why: "X falls back to Open Graph, but a card type gives control.", fix: "Add twitter:card.", example: '<meta name="twitter:card" content="summary_large_image">' });

  // --- Structured data
  const bad = p.jsonLd.filter((b) => b.error);
  if (bad.length) f.push({ id: "json-ld", title: "Invalid JSON-LD", severity: "error", detected: bad[0].error, why: "Malformed structured data is ignored.", fix: "Fix the JSON syntax." });
  else if (p.jsonLd.length) f.push({ id: "json-ld", title: "JSON-LD parses correctly", severity: "pass", detected: `${p.jsonLd.length} block(s)`, why: "Syntax valid. Eligibility for rich results must be confirmed in Google's Rich Results Test." });
  else f.push({ id: "json-ld", title: "No structured data found", severity: "info", why: "Structured data can enable rich results where eligible." });

  // --- Content
  if (p.wordCount < 300) f.push({ id: "thin-content", title: "Low word count", severity: "info", detected: `${p.wordCount} words`, why: "Very short pages may not cover the topic, though length alone is not a ranking factor." });

  // --- Links
  let internal = 0, external = 0, emptyAnchor = 0;
  for (const l of p.links) {
    let u: URL;
    try { u = new URL(l.href, ctx.finalUrl); } catch { continue; }
    if (!/^https?:$/.test(u.protocol)) continue;
    if (u.hostname === url.hostname) internal++; else external++;
    if (!l.text) emptyAnchor++;
  }
  f.push({ id: "links", title: "Link counts", severity: "info", detected: `${internal} internal, ${external} external`, why: "Internal links distribute authority and help discovery." });
  if (emptyAnchor) f.push({ id: "empty-anchor", title: "Links without anchor text", severity: "info", detected: `${emptyAnchor}`, why: "Anchor text describes the destination.", fix: "Add descriptive text or an image alt." });

  // --- Not verified here
  f.push({ id: "broken-links", title: "Broken links", severity: "unverified", why: "This single-page report did not request each linked URL. Use the broken link checker." });
  f.push({ id: "core-web-vitals", title: "Core Web Vitals", severity: "unverified", why: "This fast HTML checker does not call PageSpeed. Use the PageSpeed & Core Web Vitals tool or the Site Health Report for real lab and field data." });
  return f;
}

export function summarize(findings: Finding[]): Record<Severity, number> {
  const s: Record<Severity, number> = { error: 0, warning: 0, info: 0, pass: 0, unverified: 0 };
  for (const x of findings) s[x.severity]++;
  return s;
}
