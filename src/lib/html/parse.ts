/**
 * Lightweight, dependency-free HTML extractor for SEO analysis.
 * It never executes scripts and never renders HTML; it only reads tags.
 * (If cheerio becomes installable it can replace this behind the same interface.)
 */

export interface Heading { level: number; text: string }
export interface LinkInfo { href: string; text: string; rel: string }
export interface ImageInfo { src: string; alt: string | null }
export interface JsonLdBlock { raw: string; parsed: unknown; error?: string }
export interface HreflangInfo { lang: string; href: string }

export interface ParsedPage {
  title: string | null;
  metaDescription: string | null;
  canonical: string | null;
  robotsMeta: string | null;
  lang: string | null;
  viewport: string | null;
  charset: string | null;
  headings: Heading[];
  links: LinkInfo[];
  images: ImageInfo[];
  og: Record<string, string>;
  twitter: Record<string, string>;
  jsonLd: JsonLdBlock[];
  hreflang: HreflangInfo[];
  text: string;
  wordCount: number;
}

const ENTITIES: Record<string, string> = {
  amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", ndash: "–", mdash: "—", hellip: "…", copy: "©",
};

export function decodeEntities(s: string): string {
  return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e: string) => {
    if (e[0] === "#") {
      const code = e[1].toLowerCase() === "x" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return Number.isFinite(code) && code > 0 && code < 0x110000 ? String.fromCodePoint(code) : m;
    }
    return ENTITIES[e.toLowerCase()] ?? m;
  });
}

function stripTags(s: string): string {
  return decodeEntities(s.replace(/<[^>]*>/g, " ")).replace(/\s+/g, " ").trim();
}

export function parseAttrs(attrString: string): Record<string, string> {
  const out: Record<string, string> = {};
  const re = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(attrString))) {
    const name = m[1].toLowerCase();
    if (!(name in out)) out[name] = decodeEntities(m[2] ?? m[3] ?? m[4] ?? "");
  }
  return out;
}

export function parseHtml(html: string): ParsedPage {
  // Capture JSON-LD before scripts are removed.
  const jsonLd: JsonLdBlock[] = [];
  const ldRe = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  let sm: RegExpExecArray | null;
  while ((sm = ldRe.exec(html))) {
    const attrs = parseAttrs(sm[1]);
    if ((attrs.type ?? "").toLowerCase() === "application/ld+json") {
      const raw = sm[2].trim();
      try {
        jsonLd.push({ raw, parsed: JSON.parse(raw) });
      } catch (e) {
        jsonLd.push({ raw, parsed: null, error: (e as Error).message });
      }
    }
  }

  const clean = html
    .replace(/<!--[\s\S]*?-->/g, "")
    .replace(/<script\b[\s\S]*?<\/script>/gi, "")
    .replace(/<style\b[\s\S]*?<\/style>/gi, "");

  const headMatch = clean.match(/<head\b[^>]*>([\s\S]*?)<\/head>/i);
  const head = headMatch ? headMatch[1] : clean;
  const bodyMatch = clean.match(/<body\b[^>]*>([\s\S]*)<\/body>/i);
  const body = bodyMatch ? bodyMatch[1] : clean.replace(/<head\b[\s\S]*?<\/head>/i, "");

  const titleMatch = head.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i);
  const title = titleMatch ? stripTags(titleMatch[1]) : null;

  let metaDescription: string | null = null;
  let robotsMeta: string | null = null;
  let viewport: string | null = null;
  let charset: string | null = null;
  const og: Record<string, string> = {};
  const twitter: Record<string, string> = {};
  const metaRe = /<meta\b([^>]*)>/gi;
  let mm: RegExpExecArray | null;
  while ((mm = metaRe.exec(head))) {
    const a = parseAttrs(mm[1]);
    const name = (a.name ?? "").toLowerCase();
    const prop = (a.property ?? "").toLowerCase();
    if (a.charset) charset = a.charset;
    if (name === "description" && metaDescription === null) metaDescription = a.content ?? "";
    else if (name === "robots" && robotsMeta === null) robotsMeta = a.content ?? "";
    else if (name === "viewport") viewport = a.content ?? "";
    if (prop.startsWith("og:")) og[prop] = a.content ?? "";
    if (name.startsWith("twitter:")) twitter[name] = a.content ?? "";
    else if (prop.startsWith("twitter:")) twitter[prop] = a.content ?? "";
  }

  let canonical: string | null = null;
  const hreflang: HreflangInfo[] = [];
  const linkRe = /<link\b([^>]*)>/gi;
  let lm: RegExpExecArray | null;
  while ((lm = linkRe.exec(head))) {
    const a = parseAttrs(lm[1]);
    const rel = (a.rel ?? "").toLowerCase().split(/\s+/);
    if (rel.includes("canonical") && canonical === null) canonical = a.href ?? "";
    if (rel.includes("alternate") && a.hreflang && a.href) hreflang.push({ lang: a.hreflang, href: a.href });
  }

  const htmlTag = clean.match(/<html\b([^>]*)>/i);
  const lang = htmlTag ? parseAttrs(htmlTag[1]).lang ?? null : null;

  const headings: Heading[] = [];
  const hRe = /<h([1-6])\b[^>]*>([\s\S]*?)<\/h\1>/gi;
  let hm: RegExpExecArray | null;
  while ((hm = hRe.exec(body))) headings.push({ level: Number(hm[1]), text: stripTags(hm[2]) });

  const links: LinkInfo[] = [];
  const aRe = /<a\b([^>]*)>([\s\S]*?)<\/a>/gi;
  let am: RegExpExecArray | null;
  while ((am = aRe.exec(body))) {
    const a = parseAttrs(am[1]);
    if (a.href === undefined) continue;
    let text = stripTags(am[2]);
    if (!text) {
      const img = am[2].match(/<img\b([^>]*)>/i);
      if (img) text = parseAttrs(img[1]).alt ?? "";
    }
    links.push({ href: a.href, text, rel: (a.rel ?? "").toLowerCase() });
  }

  const images: ImageInfo[] = [];
  const iRe = /<img\b([^>]*)>/gi;
  let im: RegExpExecArray | null;
  while ((im = iRe.exec(body))) {
    const a = parseAttrs(im[1]);
    images.push({ src: a.src ?? a["data-src"] ?? "", alt: "alt" in a ? a.alt : null });
  }

  const text = stripTags(body.replace(/<(script|style|noscript|template)\b[\s\S]*?<\/\1>/gi, " "));
  const wordCount = text ? text.split(/\s+/).length : 0;

  return {
    title, metaDescription, canonical, robotsMeta, lang, viewport, charset,
    headings, links, images, og, twitter, jsonLd, hreflang, text, wordCount,
  };
}
