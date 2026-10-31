export interface RobotsRule { type: "allow" | "disallow"; path: string }
export interface RobotsGroup { agents: string[]; rules: RobotsRule[]; crawlDelay?: number }
export interface RobotsParsed { groups: RobotsGroup[]; sitemaps: string[]; warnings: string[] }

const KNOWN = new Set(["user-agent", "allow", "disallow", "sitemap", "crawl-delay", "host", "noindex"]);

export function parseRobots(text: string): RobotsParsed {
  const groups: RobotsGroup[] = [];
  const sitemaps: string[] = [];
  const warnings: string[] = [];
  let cur: RobotsGroup | null = null;
  let lastWasAgent = false;

  text.split(/\r?\n/).forEach((rawLine, idx) => {
    const line = rawLine.replace(/#.*/, "").trim();
    if (!line) return;
    const i = line.indexOf(":");
    if (i < 0) { warnings.push(`Line ${idx + 1}: not a "field: value" directive.`); return; }
    const field = line.slice(0, i).trim().toLowerCase();
    const value = line.slice(i + 1).trim();
    if (!KNOWN.has(field)) { warnings.push(`Line ${idx + 1}: unknown directive "${field}".`); return; }

    if (field === "user-agent") {
      if (!cur || !lastWasAgent) { cur = { agents: [], rules: [] }; groups.push(cur); }
      cur.agents.push(value.toLowerCase());
      lastWasAgent = true;
      return;
    }
    lastWasAgent = false;
    if (field === "sitemap") { sitemaps.push(value); return; }
    if (!cur) { warnings.push(`Line ${idx + 1}: "${field}" appears before any User-agent.`); return; }
    if (field === "allow" || field === "disallow") {
      if (value && !value.startsWith("/") && !value.startsWith("*")) warnings.push(`Line ${idx + 1}: path should start with "/" or "*".`);
      cur.rules.push({ type: field, path: value });
    } else if (field === "crawl-delay") {
      const n = Number(value);
      if (Number.isFinite(n)) cur.crawlDelay = n; else warnings.push(`Line ${idx + 1}: invalid crawl-delay.`);
    }
  });
  return { groups, sitemaps, warnings };
}

function patternToRegex(pattern: string): RegExp {
  const anchored = pattern.endsWith("$");
  const body = (anchored ? pattern.slice(0, -1) : pattern)
    .replace(/[.+?^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*");
  return new RegExp("^" + body + (anchored ? "$" : ""));
}

/** Google-style matching: most specific (longest) rule wins; allow wins ties. */
export function isAllowed(parsed: RobotsParsed, userAgent: string, path: string): { allowed: boolean; matchedRule?: RobotsRule } {
  const ua = userAgent.toLowerCase();
  let best: RobotsGroup | undefined;
  let bestLen = -1;
  for (const g of parsed.groups) {
    for (const a of g.agents) {
      if (a === "*" ? bestLen < 0 : ua.includes(a) && a.length > bestLen) {
        best = g; bestLen = a === "*" ? 0 : a.length;
      }
    }
  }
  if (!best) return { allowed: true };
  let match: RobotsRule | undefined;
  for (const r of best.rules) {
    if (r.path === "") continue; // empty disallow = allow all
    if (!patternToRegex(r.path).test(path)) continue;
    if (!match || r.path.length > match.path.length || (r.path.length === match.path.length && r.type === "allow")) match = r;
  }
  if (!match) return { allowed: true };
  return { allowed: match.type === "allow", matchedRule: match };
}

export interface RobotsGenOptions {
  allowAll?: boolean;
  disallow?: string[];
  allow?: string[];
  sitemaps?: string[];
  crawlDelay?: number;
  userAgent?: string;
}

export function generateRobots(o: RobotsGenOptions): string {
  const lines = [`User-agent: ${o.userAgent || "*"}`];
  if (o.allowAll && !(o.disallow?.length)) lines.push("Disallow:");
  for (const p of o.disallow ?? []) lines.push(`Disallow: ${p}`);
  for (const p of o.allow ?? []) lines.push(`Allow: ${p}`);
  if (o.crawlDelay) lines.push(`Crawl-delay: ${o.crawlDelay}`);
  lines.push("");
  for (const s of o.sitemaps ?? []) lines.push(`Sitemap: ${s}`);
  return lines.join("\n").trimEnd() + "\n";
}
