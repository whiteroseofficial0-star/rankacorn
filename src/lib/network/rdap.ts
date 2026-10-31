import { isIP } from "node:net";
import { safeFetch } from "../security/safe-fetch.ts";
import { parseTargetUrl } from "../security/url-guard.ts";

/**
 * Domain registration data via RDAP (the structured, free successor to WHOIS).
 * No API key and no scraping: registries publish this openly.
 */

export interface RdapInfo {
  domain: string;
  registrar: string | null;
  registered: string | null;
  expires: string | null;
  updated: string | null;
  statuses: string[];
  nameservers: string[];
  ageDays: number | null;
}

interface RdapEvent { eventAction?: string; eventDate?: string }
interface RdapEntity { roles?: string[]; vcardArray?: unknown[] }
interface RdapResponse {
  ldhName?: string;
  status?: string[];
  events?: RdapEvent[];
  nameservers?: { ldhName?: string }[];
  entities?: RdapEntity[];
}

/** Extract the "fn" (formatted name) from a vCard array, e.g. the registrar's name. */
function vcardName(entity: RdapEntity): string | null {
  const vc = entity.vcardArray;
  if (!Array.isArray(vc) || !Array.isArray(vc[1])) return null;
  for (const row of vc[1] as unknown[]) {
    if (Array.isArray(row) && row[0] === "fn" && typeof row[3] === "string") return row[3];
  }
  return null;
}

export async function rdapLookup(domainInput: string): Promise<RdapInfo> {
  const { hostname } = parseTargetUrl(`https://${domainInput.trim().replace(/^https?:\/\//i, "")}`);
  if (isIP(hostname)) throw new Error("Enter a domain name, not an IP address.");
  const domain = hostname.replace(/^www\./, "");

  const r = await safeFetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
    maxBytes: 600_000,
    timeoutMs: 12_000,
    headers: { accept: "application/rdap+json" },
  });
  if (r.status === 404) throw new Error(`No RDAP record found for ${domain}.`);
  if (r.status >= 400) throw new Error(`RDAP lookup failed with status ${r.status}.`);

  let j: RdapResponse;
  try { j = JSON.parse(r.body) as RdapResponse; } catch { throw new Error("RDAP returned an unexpected response."); }

  const event = (action: string) => j.events?.find((e) => e.eventAction === action)?.eventDate ?? null;
  const registered = event("registration");
  const expires = event("expiration");
  const updated = event("last changed") ?? event("last update of RDAP database");

  const registrarEntity = j.entities?.find((e) => e.roles?.includes("registrar"));
  const ageDays = registered ? Math.floor((Date.now() - Date.parse(registered)) / 86_400_000) : null;

  return {
    domain: j.ldhName?.toLowerCase() ?? domain,
    registrar: registrarEntity ? vcardName(registrarEntity) : null,
    registered,
    expires,
    updated,
    statuses: j.status ?? [],
    nameservers: (j.nameservers ?? []).map((n) => n.ldhName ?? "").filter(Boolean),
    ageDays: Number.isFinite(ageDays) ? ageDays : null,
  };
}
