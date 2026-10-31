import { resolve4, resolve6, resolveCname, resolveMx, resolveTxt, resolveNs, resolveSoa } from "node:dns/promises";

export const DNS_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"] as const;
export type DnsType = (typeof DNS_TYPES)[number];

export interface DnsRecord { type: string; value: string; ttl?: number }

const byCode = (e: unknown) => (e as NodeJS.ErrnoException).code ?? "";

async function forType(host: string, type: DnsType): Promise<DnsRecord[]> {
  try {
    switch (type) {
      case "A": return (await resolve4(host, { ttl: true })).map((r) => ({ type, value: r.address, ttl: r.ttl }));
      case "AAAA": return (await resolve6(host, { ttl: true })).map((r) => ({ type, value: r.address, ttl: r.ttl }));
      case "CNAME": return (await resolveCname(host)).map((value) => ({ type, value }));
      case "MX": return (await resolveMx(host)).map((mx) => ({ type, value: `${mx.priority} ${mx.exchange}` }));
      case "TXT": return (await resolveTxt(host)).map((chunks) => ({ type, value: chunks.join("") }));
      case "NS": return (await resolveNs(host)).map((value) => ({ type, value }));
      case "SOA": {
        const soa = await resolveSoa(host);
        return [{ type, value: `${soa.nsname} ${soa.hostmaster} (serial ${soa.serial}, refresh ${soa.refresh}, retry ${soa.retry}, expire ${soa.expire}, min ${soa.minttl})` }];
      }
    }
  } catch (e) {
    const code = byCode(e);
    if (code === "ENODATA" || code === "ENOTFOUND") return [];
    throw new Error(`DNS lookup failed: ${code || (e as Error).message}`);
  }
}

/**
 * Look up one record type, or every supported type when type is "ALL".
 * "ALL" tolerates per-type failures: some resolvers return EBADRESP for SOA on a
 * CNAME'd host, and one bad type must not discard the working A/CNAME records.
 * A single-type lookup still throws so the error stays visible.
 */
export async function lookupRecords(host: string, type: string): Promise<DnsRecord[]> {
  const wanted = type === "ALL" ? [...DNS_TYPES] : ([type] as DnsType[]);
  if (wanted.length === 1) return forType(host, wanted[0]);
  const settled = await Promise.allSettled(wanted.map((t) => forType(host, t)));
  const fulfilled = settled.filter((s): s is PromiseFulfilledResult<DnsRecord[]> => s.status === "fulfilled");
  if (fulfilled.length === 0) {
    const failure = settled.find((s): s is PromiseRejectedResult => s.status === "rejected");
    throw failure?.reason ?? new Error("DNS lookup failed");
  }
  return fulfilled.flatMap((s) => s.value);
}

export function isDomainInput(host: string): boolean {
  return /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/i.test(host);
}
