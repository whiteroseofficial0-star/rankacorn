# Rankacorn — free SEO tools with real analysis

Independent SEO tools platform. Not affiliated with any other brand. Rebrand with `BRAND_NAME` / `SITE_URL` in `.env`.

## Status

Runtime has **zero npm dependencies** (Node >= 22.6) and **39 working tools** verified by 36 automated tests.

### Run

    cp .env.example .env
    # optional, raises the PageSpeed quota:
    # PAGESPEED_API_KEY=your-free-key
    npm start            # http://localhost:3000
    npm test
    docker compose up --build

`npm start` loads `.env` automatically (`--env-file-if-exists`).

## What it does

### Start here: one-box site health report
- **Site Health Report** — paste one URL and get a graded A–F report covering HTTPS, homepage status, title, meta description, H1, canonical, viewport, security headers, TLS, robots.txt, sitemap, Core Web Vitals and a 10-page crawl. Every check shows what was detected, why it matters and how to fix it. Unverified checks never lower the score; warnings score half.
- The home page is that form, so there is no menu to learn.
- Instant search on `/tools` filters by task, and any tool accepts `?url=…` prefill for linking straight to a check.
- Save the whole report with **Print / Save as PDF**.

### Performance (official Google data)
- **PageSpeed & Core Web Vitals checker** — calls the PageSpeed Insights API for the Lighthouse mobile/desktop score, the Chrome UX Report field metrics (LCP, CLS, INP, FCP) and the largest byte/time opportunities. Sites without enough traffic get lab data only, labelled as such.
- The Site Health Report folds the mobile score and field vitals into its grade. If the API is slow, down or rate-limited, both checks say "not measured" and score as unverified (no penalty).
- Optional `PAGESPEED_API_KEY` raises the quota; without a key you share Google's anonymous daily quota, which is often exhausted (the tool says so and never guesses).

### Website analysis
- Website SEO checker — title, meta, headings, images, canonical, indexability, social tags, structured data
- HTTP status & redirect checker (bulk, 20 URLs)
- HTTP response header analyzer
- Robots.txt checker and tester
- XML sitemap validator and generator
- Robots.txt generator
- Web manifest generator

### Site audit & crawling (new)
- **Site crawler & technical audit** — crawl up to 50 same-host pages and report broken responses, duplicate/missing titles, missing descriptions, missing H1, thin content, missing alt text, noindex pages, redirects and robots blocking
- **Broken link checker** — test up to 100 links found on a page (internal and/or external), with final URLs and error reasons

### Keyword tools
- Google Autocomplete keyword miner (real typed queries, no API key)
- Keyword density / frequency
- Keyword list cleaner & deduplicator
- Clustering (text-based), intent classifier, long-tail and question generator

### Content tools
- Word/character counter, readability, text similarity
- SEO slug generator
- SERP snippet preview
- **Open Graph & social preview audit** — flag missing tags, generate a corrected snippet
- CSV export (UTF-8 BOM, formula-injection safe), **print / save as PDF**

### Technical SEO
- Schema (JSON-LD) generator and validator
- Hreflang and canonical generators
- .htaccess redirect generator
- **Meta tag & Open Graph generator**
- **Security headers grader (A–F)** with a fix per missing header

### Domain & security (new)
- **DNS record lookup** (A, AAAA, CNAME, MX, TXT, NS, SOA, or all)
- **SSL certificate checker** — trust chain, expiry, SANs, protocol, cipher, ALPN
- **Domain age & RDAP lookup** — registration/expiry/registrar from public registry data, no key
- URL encoder/decoder, URL parameter analyzer, UTM builder, link extractor, URL deduplicator

Every tool has a landing page with how-to, FAQs, related tools, JSON-LD, canonical, plus `sitemap.xml` and `robots.txt`.

## Security

SSRF guard (scheme/port/credentials/internal hostnames/private+reserved IPv4+IPv6/mapped IPv6/metadata),
DNS validation, connections pinned to the validated IP, redirects re-validated per hop, response size and
time limits, per-IP rate limits (stricter for network tools, strictest for crawls), CSRF origin check,
1 MB body cap, security headers + CSP, results rendered with `textContent` only. DNS, TLS and RDAP lookups
are validated before use so the tools cannot probe internal networks. Rate limiting is in-memory
(single instance).

## Deliberately not built

Accounts/auth, database/Prisma, saved audits, multi-page history, PageSpeed *history* and alerting, keyword volume
and difficulty, SERP/rank tracking, backlinks, competitor reports, AI assistant, payments/subscriptions,
admin panel, blog, ad network integration (placeholder slots only, off by default), Excel/PDF *file* export
(print-to-PDF is available), and real search volume/CPC/backlink/ranking data.

Those figures need licensed providers. None are configured, so none are faked. The RDAP, DNS, TLS and
PageSpeed lookups use free public APIs; the crawler makes its own requests.

## Before launch

- Replace privacy/terms placeholders with reviewed text.
- Set the real bot URL in `src/lib/security/safe-fetch.ts` (`USER_AGENT`).
- Put the app behind a TLS-terminating proxy.
- Move rate limiting to Redis if running more than one instance.
- Confirm the name/domain/trademark before committing to `BRAND_NAME`.
