import http from "node:http";
import { pathToFileURL } from "node:url";
import { TOOLS, CATEGORIES, bySlug, UserError, toCsv, type Tool, type ToolResult } from "./tools/registry.ts";
import { UnsafeUrlError } from "./lib/security/url-guard.ts";
import { ProviderError } from "./lib/errors.ts";
import { escapeXml } from "./lib/seo/sitemap.ts";

const BRAND = process.env.NEXT_PUBLIC_BRAND_NAME || process.env.BRAND_NAME || "Rankacorn";
const SITE = (process.env.NEXT_PUBLIC_SITE_URL || process.env.SITE_URL || "http://localhost:3000").replace(/\/$/, "");
const PORT = Number(process.env.PORT || 3000);
const ADS_ENABLED = process.env.ADS_ENABLED === "true"; // disabled until an ad network approves the site
const MAX_BODY = 1_000_000;

const esc = escapeXml;

/** Render the wordmark with the "rank" root in ink and the rest in the accent colour. */
function brandMark(): string {
  const m = BRAND.match(/^(rank)(.+)$/i);
  return m ? `${esc(m[1])}<span>${esc(m[2])}</span>` : `${esc(BRAND.slice(0, 1))}<span>${esc(BRAND.slice(1))}</span>`;
}

// ---------- rate limiting (in-memory; replace with Redis in multi-instance deploys)
const buckets = new Map<string, { count: number; reset: number }>();
function limited(key: string, max: number, windowMs = 60_000): boolean {
  const now = Date.now();
  const b = buckets.get(key);
  if (!b || b.reset < now) { buckets.set(key, { count: 1, reset: now + windowMs }); return false; }
  return ++b.count > max;
}
setInterval(() => { const n = Date.now(); for (const [k, v] of buckets) if (v.reset < n) buckets.delete(k); }, 60_000).unref();

// ---------- HTML layout
const CSS = `:root{--ink:#0b1b3b;--muted:#51607a;--bg:#f7f8fb;--card:#fff;--line:#e3e7ef;--accent:#e4572e;--accent-ink:#fff}
@media (prefers-color-scheme:dark){:root{--ink:#e8edf7;--muted:#9fb0cc;--bg:#0c1426;--card:#121c33;--line:#243251;--accent:#ff7a52;--accent-ink:#0c1426}}
*{box-sizing:border-box}body{margin:0;font:16px/1.6 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:var(--ink);background:var(--bg)}
a{color:inherit}.wrap{max-width:1080px;margin:0 auto;padding:0 16px}header{background:var(--card);border-bottom:1px solid var(--line)}
header .wrap{display:flex;align-items:center;justify-content:space-between;height:64px}.logo{font-weight:800;font-size:1.25rem;text-decoration:none}.logo span{color:var(--accent)}
nav a{margin-left:20px;text-decoration:none;color:var(--muted)}nav a:hover,nav a:focus{color:var(--ink);text-decoration:underline}
h1{font-size:clamp(1.8rem,4vw,2.6rem);line-height:1.2;margin:.6em 0 .3em}h2{margin-top:1.8em}.lead{color:var(--muted);font-size:1.1rem;max-width:62ch}
.grid{display:grid;gap:16px;grid-template-columns:repeat(auto-fill,minmax(260px,1fr))}.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px}
.card h3{margin:.1em 0 .3em;font-size:1.05rem}.card p{margin:0;color:var(--muted);font-size:.95rem}.card a{text-decoration:none}.card:hover{border-color:var(--accent)}
.tag{font-size:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
form label{display:block;font-weight:600;margin:14px 0 4px}input,textarea,select{width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--ink);font:inherit}
textarea{min-height:130px}button,.btn{background:var(--accent);color:var(--accent-ink);border:0;border-radius:8px;padding:11px 20px;font:inherit;font-weight:700;cursor:pointer;margin-top:16px;text-decoration:none;display:inline-block}
button.secondary{background:transparent;color:var(--ink);border:1px solid var(--line);margin-left:8px}:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
.help{font-size:.85rem;color:var(--muted)}table{border-collapse:collapse;width:100%;font-size:.92rem}th,td{border-bottom:1px solid var(--line);padding:8px;text-align:left;vertical-align:top;word-break:break-word}
.sev{display:inline-block;padding:1px 8px;border-radius:99px;font-size:.75rem;font-weight:700}.sev.error{background:#fde2dd;color:#8a1c0a}.sev.warning{background:#fdf0cf;color:#6b4a00}.sev.info{background:#dfe9fb;color:#173a7a}.sev.pass{background:#d8f3e0;color:#0b5a26}.sev.unverified{background:#e6e6ea;color:#40404a}
pre{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px;overflow:auto;white-space:pre-wrap;word-break:break-word}.crumbs{font-size:.88rem;color:var(--muted);margin-top:18px}.crumbs a{color:var(--muted)}
footer{margin-top:60px;border-top:1px solid var(--line);padding:24px 0;color:var(--muted);font-size:.9rem}.err{border:1px solid #d9534f;background:#fde2dd;color:#8a1c0a;padding:10px 14px;border-radius:8px}
.sum{display:flex;gap:10px;flex-wrap:wrap;margin:12px 0}.ad{margin:24px 0;min-height:90px;border:1px dashed var(--line);text-align:center;color:var(--muted);font-size:.8rem;padding:8px}
details{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 14px;margin:8px 0}summary{cursor:pointer;font-weight:600}
#filter{margin:10px 0 0}section.cat{scroll-margin-top:80px}
@media print{header,footer,form,.ad,.crumbs,.no-print{display:none!important}body{background:#fff;color:#000}main{max-width:none;padding:0}#out{margin:0}h1,h2{break-after:avoid}.card,pre,table,tr{break-inside:avoid}pre{white-space:pre-wrap}a{text-decoration:none}}`;

function layout(o: { title: string; description: string; path: string; body: string; jsonLd?: unknown; noindex?: boolean }): string {
  const url = SITE + o.path;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(o.title)}</title><meta name="description" content="${esc(o.description)}"><link rel="canonical" href="${esc(url)}">
${o.noindex ? '<meta name="robots" content="noindex">' : ""}<meta property="og:title" content="${esc(o.title)}"><meta property="og:description" content="${esc(o.description)}"><meta property="og:url" content="${esc(url)}"><meta property="og:type" content="website"><meta name="twitter:card" content="summary">
${o.jsonLd ? `<script type="application/ld+json">${JSON.stringify(o.jsonLd).replace(/</g, "\\u003c")}</script>` : ""}<style>${CSS}</style></head><body>
<a href="#main" style="position:absolute;left:-999px">Skip to content</a>
<header><div class="wrap"><a class="logo" href="/">${brandMark()}</a><nav aria-label="Main"><a href="/tools">Tools</a><a href="/tools/site-crawler-audit">Site audit</a><a href="/about">About</a><a href="/privacy">Privacy</a></nav></div></header>
<main id="main" class="wrap">${o.body}</main>
<footer><div class="wrap">&copy; ${new Date().getFullYear()} ${esc(BRAND)}. Free SEO tools. Results are informational and do not guarantee rankings. <a href="/privacy">Privacy</a> &middot; <a href="/terms">Terms</a></div></footer></body></html>`;
}

const ad = (slot: string) => (ADS_ENABLED ? `<div class="ad" data-slot="${esc(slot)}" aria-label="Advertisement">Advertisement</div>` : "");

const toolCard = (t: Tool) => `<div class="card"><div class="tag">${esc(t.category)}</div><h3><a href="/tools/${t.slug}">${esc(t.name)}</a></h3><p>${esc(t.summary)}</p></div>`;

function homePage() {
  return layout({
    title: `${BRAND} - Free SEO Tools for Websites, Keywords and Content`, description: `${TOOLS.length} working SEO tools: website checker, robots.txt and sitemap tools, keyword utilities and content analysis. No signup needed.`, path: "/",
    jsonLd: { "@context": "https://schema.org", "@type": "WebSite", name: BRAND, url: SITE },
    body: `<h1>Free SEO tools that do real analysis</h1><p class="lead">Check a page, test robots.txt, validate sitemaps, clean keyword lists and generate technical SEO files. Nothing is invented: when a metric needs a data provider, we say so.</p>
<form class="card" method="get" action="/tools/site-health-report"><label for="h_url">Run a free site health check</label><input id="h_url" name="url" type="text" inputmode="url" autocomplete="url" placeholder="https://example.com" required><div class="help">DNS, TLS, security headers, robots.txt, sitemap, Core Web Vitals and up to 10 crawled pages in one A–F report. No signup.</div><button type="submit">Check my site</button></form>${ad("home-top")}<h2>Popular tools</h2><div class="grid">${TOOLS.slice(0, 6).map(toolCard).join("")}</div>
<h2>Browse by category</h2><div class="grid">${CATEGORIES.map((c) => `<div class="card"><h3><a href="/tools#${slug(c)}">${esc(c)}</a></h3><p>${TOOLS.filter((t) => t.category === c).length} tools</p></div>`).join("")}</div>`,
  });
}
const slug = (s: string) => s.toLowerCase().replace(/[^a-z0-9]+/g, "-");

function directoryPage() {
  return layout({
    title: `All SEO Tools | ${BRAND}`, description: `Browse every ${BRAND} SEO tool by category: website analysis, keyword tools, content tools, technical SEO and link utilities.`, path: "/tools",
    jsonLd: { "@context": "https://schema.org", "@type": "ItemList", itemListElement: TOOLS.map((t, i) => ({ "@type": "ListItem", position: i + 1, url: `${SITE}/tools/${t.slug}`, name: t.name })) },
    body: `<nav class="crumbs" aria-label="Breadcrumb"><a href="/">Home</a> &rsaquo; Tools</nav><h1>All SEO tools</h1><p class="lead">${TOOLS.length} free tools. Search by task, or jump to a category.</p>
<input id="filter" type="search" placeholder="Search ${TOOLS.length} tools, e.g. robots, sitemap, ssl…" aria-label="Search tools" autocomplete="off">
<p class="help" id="filterCount" aria-live="polite"></p>
${CATEGORIES.map((c) => `<section class="cat"><h2 id="${slug(c)}">${esc(c)}</h2><div class="grid">${TOOLS.filter((t) => t.category === c).map(toolCard).join("")}</div></section>`).join("")}
<script>(function(){var i=document.getElementById('filter'),n=document.getElementById('filterCount');if(!i)return;var secs=[].slice.call(document.querySelectorAll('section.cat'));function run(){var q=i.value.toLowerCase().trim(),total=0;secs.forEach(function(s){var shown=0;[].slice.call(s.querySelectorAll('.card')).forEach(function(c){var ok=!q||c.textContent.toLowerCase().indexOf(q)!==-1;c.hidden=!ok;if(ok)shown++});s.hidden=shown===0;total+=shown});n.textContent=total+' tool'+(total===1?'':'s')+(q?' matching "'+i.value+'"':'')}i.addEventListener('input',run);run()})();</script>`,
  });
}

function toolPage(t: Tool, prefill: Record<string, string> = {}) {
  const fields = t.fields.map((f) => {
    const id = `f_${f.name}`;
    const pre = prefill[f.name] ?? "";
    const common = `id="${id}" name="${f.name}"${f.required ? " required" : ""}${f.placeholder ? ` placeholder="${esc(f.placeholder)}"` : ""}`;
    const input = f.type === "textarea"
      ? `<textarea ${common}>${esc(pre)}</textarea>`
      : f.type === "select"
        ? `<select ${common}>${(f.options ?? []).map((o, idx) => `<option value="${esc(o)}"${o === pre || (!pre && idx === 0) ? " selected" : ""}>${esc(o || "(none)")}</option>`).join("")}</select>`
        : `<input ${common} type="${f.type === "url" ? "text" : f.type}" value="${esc(pre)}" ${f.type === "url" ? 'inputmode="url" autocomplete="url"' : ""}>`;
    return `<label for="${id}">${esc(f.label)}</label>${input}${f.help ? `<div class="help">${esc(f.help)}</div>` : ""}`;
  }).join("");
  const related = t.related.map((s) => bySlug.get(s)).filter((x): x is Tool => !!x);
  return layout({
    title: `${t.name} — Free, No Signup | ${BRAND}`, description: t.summary, path: `/tools/${t.slug}`,
    jsonLd: [
      { "@context": "https://schema.org", "@type": "BreadcrumbList", itemListElement: [{ "@type": "ListItem", position: 1, name: "Home", item: SITE + "/" }, { "@type": "ListItem", position: 2, name: "Tools", item: SITE + "/tools" }, { "@type": "ListItem", position: 3, name: t.name, item: `${SITE}/tools/${t.slug}` }] },
      { "@context": "https://schema.org", "@type": "FAQPage", mainEntity: t.faqs.map((f) => ({ "@type": "Question", name: f.q, acceptedAnswer: { "@type": "Answer", text: f.a } })) },
    ],
    body: `<nav class="crumbs" aria-label="Breadcrumb"><a href="/">Home</a> &rsaquo; <a href="/tools">Tools</a> &rsaquo; ${esc(t.name)}</nav><h1>${esc(t.name)}</h1><p class="lead">${esc(t.summary)}</p>${ad("tool-top")}
<form id="tool" class="card" novalidate>${fields}<div><button type="submit">Run tool</button><button type="button" class="secondary" id="csv" hidden>Download CSV</button><button type="button" class="secondary" id="dl" hidden>Download file</button><button type="button" class="secondary" id="copy" hidden>Copy</button><button type="button" class="secondary" id="print" hidden>Print / Save PDF</button></div></form>
<div id="out" aria-live="polite"></div>
<div class="no-print"><h2>How to use</h2><ol>${t.howTo.map((h) => `<li>${esc(h)}</li>`).join("")}</ol>
<h2>Frequently asked questions</h2>${t.faqs.map((f) => `<details><summary>${esc(f.q)}</summary><p>${esc(f.a)}</p></details>`).join("")}
${related.length ? `<h2>Related tools</h2><div class="grid">${related.map(toolCard).join("")}</div>` : ""}</div>${ad("tool-bottom")}
<script>${CLIENT_JS.replaceAll("__SLUG__", t.slug)}</script>`,
  });
}

// Client-side script builds results with textContent only (no innerHTML), so output can never inject markup.
const CLIENT_JS = `(function(){var form=document.getElementById('tool'),out=document.getElementById('out'),csvBtn=document.getElementById('csv'),dlBtn=document.getElementById('dl'),copyBtn=document.getElementById('copy'),printBtn=document.getElementById('print'),last=null,order={error:0,warning:1,info:2,unverified:3,pass:4};
function el(t,c,x){var e=document.createElement(t);if(c)e.className=c;if(x!==undefined)e.textContent=x;return e}
function table(cols,rows){var t=el('table'),h=el('tr');cols.forEach(function(c){h.appendChild(el('th','',c))});t.appendChild(h);rows.forEach(function(r){var tr=el('tr');r.forEach(function(v){tr.appendChild(el('td','',String(v)))});t.appendChild(tr)});return t}
function save(name,text,mime){var b=new Blob([text],{type:mime}),a=document.createElement('a');a.href=URL.createObjectURL(b);a.download=name;a.click();setTimeout(function(){URL.revokeObjectURL(a.href)},1000)}
function findingsBox(r){var f=document.createDocumentFragment();
if(r.summary){var s=el('div','sum');['error','warning','info','pass','unverified'].forEach(function(k){s.appendChild(el('span','sev '+k,(r.summary[k]||0)+' '+k))});f.appendChild(s)}
if(r.meta){f.appendChild(el('p','help',Object.keys(r.meta).map(function(k){return k+': '+r.meta[k]}).join(' | ')))}
(r.findings||[]).slice().sort(function(a,b){return order[a.severity]-order[b.severity]}).forEach(function(x){var c=el('div','card');c.style.marginTop='10px';var h=el('div');h.appendChild(el('span','sev '+x.severity,x.severity==='unverified'?'not verified':x.severity));h.appendChild(el('strong','',' '+x.title));c.appendChild(h);
[['Detected',x.detected],['Element',x.element],['Why it matters',x.why],['Recommended fix',x.fix]].forEach(function(p){if(p[1])c.appendChild(el('p','help',p[0]+': '+p[1]))});if(x.example)c.appendChild(el('pre','',x.example));f.appendChild(c)});return f}
function render(r){out.textContent='';csvBtn.hidden=true;dlBtn.hidden=true;copyBtn.hidden=true;printBtn.hidden=false;last=r;
if(r.kind==='findings'){out.appendChild(findingsBox(r))}
else if(r.kind==='table'){if(r.findings||r.summary)out.appendChild(findingsBox(r));if(r.note)out.appendChild(el('p','',r.note));var wrap=el('div');wrap.style.overflowX='auto';wrap.appendChild(table(r.columns,r.rows));out.appendChild(wrap);if(r.csv)csvBtn.hidden=false}
else if(r.kind==='text'){if(r.note)out.appendChild(el('p','help',r.note));out.appendChild(el('pre','',r.text));if(r.filename)dlBtn.hidden=false;copyBtn.hidden=false}
else if(r.kind==='keyvalue'){if(r.note)out.appendChild(el('p','help',r.note));out.appendChild(table(['Item','Value'],r.items))}}
function showError(msg){out.textContent='';out.appendChild(el('div','err',msg))}
form.addEventListener('submit',function(e){e.preventDefault();var data={};new FormData(form).forEach(function(v,k){data[k]=String(v)});out.textContent='Working…';csvBtn.hidden=true;dlBtn.hidden=true;copyBtn.hidden=true;printBtn.hidden=true;
fetch('/api/tools/__SLUG__',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(data)}).then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j}})}).then(function(x){if(!x.ok){showError(x.j.error||'Something went wrong.');return}render(x.j.result)}).catch(function(){showError('Network error. Please try again.')})});
csvBtn.addEventListener('click',function(){if(!last)return;var rows=[last.columns].concat(last.rows);fetch('/api/csv',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({rows:rows})}).then(function(r){return r.text()}).then(function(t){save('__SLUG__.csv',t,'text/csv;charset=utf-8')})});
dlBtn.addEventListener('click',function(){if(last&&last.filename)save(last.filename,last.text,last.mime||'text/plain')});
copyBtn.addEventListener('click',function(){if(!last||!last.text)return;var done=function(){copyBtn.textContent='Copied';setTimeout(function(){copyBtn.textContent='Copy'},1500)};if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(last.text).then(done,function(){})}else{var a=el('textarea');a.value=last.text;document.body.appendChild(a);a.select();try{document.execCommand('copy');done()}catch(x){}document.body.removeChild(a)}});
printBtn.addEventListener('click',function(){window.print()})})();`;

const staticPage = (path: string, title: string, body: string) => layout({ title: `${title} | ${BRAND}`, description: `${title} for ${BRAND}.`, path, body: `<h1>${esc(title)}</h1>${body}` });
const PAGES: Record<string, () => string> = {
  "/about": () => staticPage("/about", "About", `<p>${esc(BRAND)} is an independent set of SEO utilities. Every result comes from analysing the page or text you provide. We do not show search volume, backlink counts or performance scores unless a licensed data source is configured.</p>`),
  "/privacy": () => staticPage("/privacy", "Privacy Policy", `<p>Tools process the text and URLs you submit to produce a result. This build stores no accounts and keeps no submissions. Your IP address is used in memory for rate limiting only. Replace this page with a full policy reviewed for your jurisdiction before launch.</p>`),
  "/terms": () => staticPage("/terms", "Terms of Use", `<p>Use the tools only on sites you are permitted to analyse. Results are informational and do not guarantee search rankings. Replace with reviewed terms before launch.</p>`),
};

// ---------- HTTP plumbing
const SECURITY_HEADERS: Record<string, string> = {
  "x-content-type-options": "nosniff", "x-frame-options": "DENY", "referrer-policy": "strict-origin-when-cross-origin",
  "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
};

function send(res: http.ServerResponse, status: number, body: string, type = "text/html; charset=utf-8", extra: Record<string, string> = {}) {
  res.writeHead(status, { "content-type": type, ...SECURITY_HEADERS, ...extra });
  res.end(body);
}
const json = (res: http.ServerResponse, status: number, obj: unknown) => send(res, status, JSON.stringify(obj), "application/json; charset=utf-8", { "cache-control": "no-store" });

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => { size += c.length; if (size > MAX_BODY) { reject(new UserError("Request too large (1 MB max).")); req.destroy(); } else chunks.push(c); });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

const notFound = () => layout({ title: `Page not found | ${BRAND}`, description: "Page not found.", path: "/404", noindex: true, body: `<h1>Page not found</h1><p><a href="/tools">Browse all tools</a></p>` });

export async function handle(req: http.IncomingMessage, res: http.ServerResponse) {
  const url = new URL(req.url || "/", SITE);
  const path = url.pathname.replace(/(.)\/$/, "$1");
  const ip = req.socket.remoteAddress || "unknown";
  try {
    if (req.method === "GET" || req.method === "HEAD") {
      if (path === "/") return send(res, 200, homePage());
      if (path === "/tools") return send(res, 200, directoryPage());
      const m = path.match(/^\/tools\/([a-z0-9-]+)$/);
      if (m) { const t = bySlug.get(m[1]); return t ? send(res, 200, toolPage(t, Object.fromEntries(url.searchParams))) : send(res, 404, notFound()); }
      if (PAGES[path]) return send(res, 200, PAGES[path]());
      if (path === "/robots.txt") return send(res, 200, `User-agent: *\nAllow: /\nDisallow: /api/\n\nSitemap: ${SITE}/sitemap.xml\n`, "text/plain");
      if (path === "/sitemap.xml") {
        const urls = ["/", "/tools", "/about", "/privacy", "/terms", ...TOOLS.map((t) => `/tools/${t.slug}`)];
        return send(res, 200, `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.map((u) => `  <url><loc>${esc(SITE + u)}</loc></url>`).join("\n")}\n</urlset>\n`, "application/xml");
      }
      if (path === "/healthz") return json(res, 200, { ok: true });
      return send(res, 404, notFound());
    }
    if (req.method === "POST") {
      if (!(req.headers["content-type"] || "").includes("application/json")) return json(res, 415, { error: "Send JSON." });
      // CSRF: reject cross-site browser requests.
      const origin = req.headers.origin;
      if (origin && new URL(origin).host !== (req.headers.host || "")) return json(res, 403, { error: "Cross-origin requests are not allowed." });
      if (path === "/api/csv") {
        if (limited(`csv:${ip}`, 60)) return json(res, 429, { error: "Too many requests." });
        const b = JSON.parse(await readBody(req));
        if (!Array.isArray(b.rows) || b.rows.length > 100_000) return json(res, 400, { error: "Invalid rows." });
        return send(res, 200, toCsv(b.rows), "text/csv; charset=utf-8", { "content-disposition": 'attachment; filename="export.csv"' });
      }
      const m = path.match(/^\/api\/tools\/([a-z0-9-]+)$/);
      const t = m && bySlug.get(m[1]);
      if (!t) return json(res, 404, { error: "Unknown tool." });
      if (limited(`any:${ip}`, 60)) return json(res, 429, { error: "Rate limit reached. Please wait a minute." });
      if (t.heavy && limited(`heavy:${ip}`, 3)) return json(res, 429, { error: "Crawls are limited to 3 per minute. Please wait a minute." });
      if (t.network && limited(`net:${ip}`, 10)) return json(res, 429, { error: "Too many website checks. Please wait a minute." });
      let input: Record<string, string>;
      try { input = JSON.parse(await readBody(req)); } catch (e) { if (e instanceof UserError) return json(res, 413, { error: e.message }); return json(res, 400, { error: "Invalid JSON." }); }
      if (!input || typeof input !== "object" || Array.isArray(input)) return json(res, 400, { error: "Invalid input." });
      const clean: Record<string, string> = {};
      for (const f of t.fields) { const v = input[f.name]; clean[f.name] = typeof v === "string" ? v.slice(0, 200_000) : ""; }
      const result: ToolResult = await t.run(clean);
      return json(res, 200, { result });
    }
    return send(res, 405, "Method not allowed", "text/plain");
  } catch (e) {
    if (e instanceof UserError || e instanceof UnsafeUrlError) return json(res, 400, { error: e.message });
    if (e instanceof ProviderError) return json(res, 502, { error: e.message });
    const err = e as NodeJS.ErrnoException;
    if (req.method === "POST") {
      const msg = /timed out/i.test(err.message) ? "The site took too long to respond." : err.code === "ECONNREFUSED" ? "Connection refused by the site." : err.code === "ENOTFOUND" ? "Domain could not be found." : /certificate|SSL|TLS/i.test(err.message) ? "The site's TLS certificate could not be verified." : "Could not complete the request.";
      console.error(JSON.stringify({ level: "error", path, message: err.message }));
      return json(res, 502, { error: msg });
    }
    console.error(JSON.stringify({ level: "error", path, message: err.message }));
    return send(res, 500, "Server error", "text/plain");
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  http.createServer(handle).listen(PORT, () => console.log(`${BRAND} listening on ${SITE.replace(/:\d+$/, "")}:${PORT}`));
}
