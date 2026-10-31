import http from "node:http";
import https from "node:https";
import type { LookupFunction } from "node:dns";
import { assertSafeUrl, UnsafeUrlError, type Resolver } from "./url-guard.ts";

export interface SafeFetchOptions {
  method?: "GET" | "HEAD";
  timeoutMs?: number; // total per hop
  maxBytes?: number; // body cap
  maxRedirects?: number;
  headers?: Record<string, string>;
  resolver?: Resolver; // injectable for tests
}

export interface Hop {
  url: string;
  status: number;
  location?: string;
  timeMs: number;
}

export interface SafeFetchResult {
  finalUrl: string;
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
  truncated: boolean;
  hops: Hop[]; // full redirect chain, last entry is the final response
  totalMs: number;
}

const DEFAULTS = { timeoutMs: 10_000, maxBytes: 2_000_000, maxRedirects: 10 };
export const USER_AGENT = "RankacornBot/0.2 (+https://example.com/bot)";

function requestOnce(
  url: URL,
  ip: string,
  opts: Required<Pick<SafeFetchOptions, "timeoutMs" | "maxBytes">> & SafeFetchOptions,
): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string; truncated: boolean }> {
  return new Promise((resolve, reject) => {
    const lib = url.protocol === "https:" ? https : http;
    // Pin the socket to the address we already validated, so DNS cannot change between check and connect.
    const pinned: LookupFunction = (_host, options, cb) => {
      const family = ip.includes(":") ? 6 : 4;
      if ((options as { all?: boolean }).all) {
        (cb as unknown as (e: null, a: { address: string; family: number }[]) => void)(null, [{ address: ip, family }]);
      } else {
        cb(null, ip, family);
      }
    };
    const req = lib.request(
      url,
      {
        method: opts.method ?? "GET",
        lookup: pinned,
        headers: { "user-agent": USER_AGENT, accept: "text/html,*/*;q=0.8", "accept-encoding": "identity", ...opts.headers },
        timeout: opts.timeoutMs,
      },
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        let truncated = false;
        res.on("data", (c: Buffer) => {
          size += c.length;
          if (size > opts.maxBytes) {
            truncated = true;
            chunks.push(c.subarray(0, c.length - (size - opts.maxBytes)));
            res.destroy();
            return;
          }
          chunks.push(c);
        });
        const done = () =>
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString("utf8"),
            truncated,
          });
        res.on("end", done);
        res.on("close", done);
        res.on("error", reject);
      },
    );
    req.on("timeout", () => req.destroy(new Error("Request timed out.")));
    req.on("error", reject);
    req.end();
  });
}

/**
 * Fetch a public URL on behalf of a user. Redirects are followed manually and
 * every hop is re-validated against the SSRF guard.
 */
export async function safeFetch(input: string, options: SafeFetchOptions = {}): Promise<SafeFetchResult> {
  const opts = { ...DEFAULTS, ...options };
  const started = Date.now();
  const hops: Hop[] = [];
  let current = input;

  for (let i = 0; i <= opts.maxRedirects; i++) {
    const { url, addresses } = await assertSafeUrl(current, opts.resolver);
    const t0 = Date.now();
    const res = await requestOnce(url, addresses[0], opts);
    const location = typeof res.headers.location === "string" ? res.headers.location : undefined;
    hops.push({ url: url.href, status: res.status, location, timeMs: Date.now() - t0 });

    if (res.status >= 300 && res.status < 400 && location) {
      current = new URL(location, url).href; // revalidated at top of next loop
      continue;
    }
    return {
      finalUrl: url.href,
      status: res.status,
      headers: res.headers,
      body: res.body,
      truncated: res.truncated,
      hops,
      totalMs: Date.now() - started,
    };
  }
  throw new UnsafeUrlError(`Too many redirects (more than ${opts.maxRedirects}).`, "too_many_redirects");
}
