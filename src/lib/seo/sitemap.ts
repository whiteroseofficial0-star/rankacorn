export interface SitemapUrl { loc: string; lastmod?: string; changefreq?: string; priority?: number }
export interface SitemapParsed {
  type: "urlset" | "sitemapindex" | "unknown";
  urls: SitemapUrl[]; // for an index, these are child sitemaps
  errors: string[];
  warnings: string[];
}

const FREQ = new Set(["always", "hourly", "daily", "weekly", "monthly", "yearly", "never"]);
const W3C_DATE = /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:\d{2})?)?$/;

const unescapeXml = (s: string) =>
  s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, "&");
export const escapeXml = (s: string) =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;");

const tag = (block: string, name: string) => {
  const m = block.match(new RegExp(`<(?:\\w+:)?${name}\\b[^>]*>([\\s\\S]*?)</(?:\\w+:)?${name}>`, "i"));
  return m ? unescapeXml(m[1].replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1").trim()) : undefined;
};

export function parseSitemap(xml: string): SitemapParsed {
  const res: SitemapParsed = { type: "unknown", urls: [], errors: [], warnings: [] };
  const body = xml.replace(/<!--[\s\S]*?-->/g, "");
  if (/<(?:\w+:)?sitemapindex\b/i.test(body)) res.type = "sitemapindex";
  else if (/<(?:\w+:)?urlset\b/i.test(body)) res.type = "urlset";
  else { res.errors.push("Root element must be <urlset> or <sitemapindex>."); return res; }

  const itemName = res.type === "urlset" ? "url" : "sitemap";
  const re = new RegExp(`<(?:\\w+:)?${itemName}\\b[^>]*>([\\s\\S]*?)</(?:\\w+:)?${itemName}>`, "gi");
  let m: RegExpExecArray | null;
  const seen = new Set<string>();
  while ((m = re.exec(body))) {
    const loc = tag(m[1], "loc");
    if (!loc) { res.errors.push(`A <${itemName}> entry has no <loc>.`); continue; }
    const item: SitemapUrl = { loc };
    try {
      const u = new URL(loc);
      if (!/^https?:$/.test(u.protocol)) res.errors.push(`Not an http(s) URL: ${loc}`);
    } catch { res.errors.push(`Invalid URL: ${loc}`); }
    if (loc.length > 2048) res.errors.push(`URL exceeds 2048 characters: ${loc.slice(0, 60)}…`);
    if (seen.has(loc)) res.warnings.push(`Duplicate URL: ${loc}`);
    seen.add(loc);
    const lastmod = tag(m[1], "lastmod");
    if (lastmod) { item.lastmod = lastmod; if (!W3C_DATE.test(lastmod)) res.warnings.push(`lastmod is not W3C format for ${loc}: ${lastmod}`); }
    if (res.type === "urlset") {
      const cf = tag(m[1], "changefreq");
      if (cf) { item.changefreq = cf; if (!FREQ.has(cf.toLowerCase())) res.warnings.push(`Invalid changefreq "${cf}" for ${loc}`); }
      const pr = tag(m[1], "priority");
      if (pr !== undefined) {
        const n = Number(pr);
        if (!Number.isFinite(n) || n < 0 || n > 1) res.warnings.push(`priority must be 0.0-1.0 for ${loc}`); else item.priority = n;
      }
    }
    res.urls.push(item);
  }
  if (res.urls.length === 0) res.warnings.push("No entries found.");
  if (res.urls.length > 50000) res.errors.push(`Contains ${res.urls.length} entries; the limit is 50,000 per file.`);
  return res;
}

export function generateSitemap(urls: SitemapUrl[]): string {
  const items = urls.map((u) => {
    const parts = [`    <loc>${escapeXml(u.loc)}</loc>`];
    if (u.lastmod) parts.push(`    <lastmod>${escapeXml(u.lastmod)}</lastmod>`);
    if (u.changefreq) parts.push(`    <changefreq>${escapeXml(u.changefreq)}</changefreq>`);
    if (u.priority !== undefined) parts.push(`    <priority>${u.priority.toFixed(1)}</priority>`);
    return `  <url>\n${parts.join("\n")}\n  </url>`;
  });
  return `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${items.join("\n")}\n</urlset>\n`;
}
