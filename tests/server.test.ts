import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { handle } from "../src/server.ts";
import { TOOLS } from "../src/tools/registry.ts";

function start(): Promise<{ base: string; close: () => void }> {
  return new Promise((resolve) => {
    const s = http.createServer(handle).listen(0, "127.0.0.1", () => {
      const { port } = s.address() as { port: number };
      resolve({ base: `http://127.0.0.1:${port}`, close: () => s.close() });
    });
  });
}
const post = (base: string, path: string, body: unknown, headers: Record<string, string> = {}) =>
  fetch(base + path, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });

test("every tool has a unique slug, FAQs and an indexable page with metadata", async () => {
  const { base, close } = await start();
  try {
    assert.equal(new Set(TOOLS.map((t) => t.slug)).size, TOOLS.length);
    for (const t of TOOLS) {
      assert.ok(t.faqs.length > 0 && t.howTo.length > 0, t.slug);
      const html = await (await fetch(`${base}/tools/${t.slug}`)).text();
      assert.match(html, /<title>.+<\/title>/);
      assert.match(html, /rel="canonical"/);
      assert.match(html, /application\/ld\+json/);
    }
    assert.equal((await fetch(`${base}/tools/missing`)).status, 404);
    assert.match(await (await fetch(`${base}/sitemap.xml`)).text(), /tools\/word-counter/);
  } finally { close(); }
});

test("API: success, validation, SSRF refusal, CSRF refusal, CSV export", async () => {
  const { base, close } = await start();
  try {
    const ok = await post(base, "/api/tools/slug-generator", { title: "Hello World!" });
    assert.equal((await ok.json()).result.text, "hello-world");
    assert.equal((await post(base, "/api/tools/slug-generator", {})).status, 400);
    const ssrf = await post(base, "/api/tools/http-status-checker", { urls: "http://169.254.169.254/latest/meta-data/" });
    const row = (await ssrf.json()).result.rows[0];
    assert.equal(row[1], "error");
    assert.match(row[3], /Private or reserved|not allowed/);
    assert.equal((await post(base, "/api/tools/slug-generator", { title: "x" }, { origin: "http://evil.example" })).status, 403);
    const buf = Buffer.from(await (await post(base, "/api/csv", { rows: [["a", "b"], ["=1+1", "x,y"]] })).arrayBuffer());
    assert.deepEqual([...buf.subarray(0, 3)], [0xef, 0xbb, 0xbf]); // UTF-8 BOM for Excel
    const text = buf.toString("utf8");
    assert.match(text, /'=1\+1,"x,y"/);
    const bad = await fetch(`${base}/api/tools/slug-generator`, { method: "POST", headers: { "content-type": "text/plain" }, body: "x" });
    assert.equal(bad.status, 415);
  } finally { close(); }
});

test("responses carry security headers", async () => {
  const { base, close } = await start();
  try {
    const r = await fetch(base + "/");
    assert.equal(r.headers.get("x-content-type-options"), "nosniff");
    assert.match(r.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'/);
  } finally { close(); }
});

test("one-box health check: home form, tools search and URL prefill", async () => {
  const { base, close } = await start();
  try {
    const home = await (await fetch(base + "/")).text();
    assert.match(home, /action="\/tools\/site-health-report"/);
    const tools = await (await fetch(base + "/tools")).text();
    assert.match(tools, /id="filter"/);
    assert.match(tools, /section class="cat"/);

    const pref = await (await fetch(`${base}/tools/site-health-report?url=${encodeURIComponent("https://example.com/a?b=1")}`)).text();
    assert.match(pref, /name="url"/);
    assert.match(pref, /value="https:\/\/example\.com\/a\?b=1"/);
    assert.match(pref, /id="copy"/);
    assert.match(pref, /id="print"/);
  } finally { close(); }
});
