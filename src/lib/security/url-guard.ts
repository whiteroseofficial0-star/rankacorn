import { BlockList, isIP } from "node:net";
import { lookup } from "node:dns/promises";

/**
 * SSRF protection. Every outbound request made on behalf of a user must pass
 * through assertSafeUrl(), including each redirect hop.
 */

export class UnsafeUrlError extends Error {
  readonly code: string;
  constructor(message: string, code: string) {
    super(message);
    this.name = "UnsafeUrlError";
    this.code = code;
  }
}

const blocked = new BlockList();
// IPv4
for (const [net, prefix] of [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10], // carrier-grade NAT
  ["127.0.0.0", 8],
  ["169.254.0.0", 16], // link-local, includes cloud metadata 169.254.169.254
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4], // multicast
  ["240.0.0.0", 4], // reserved + broadcast
] as const) {
  blocked.addSubnet(net, prefix, "ipv4");
}
// IPv6
for (const [net, prefix] of [
  ["::", 128],
  ["::1", 128],
  ["64:ff9b::", 96],
  ["100::", 64],
  ["2001:db8::", 32],
  ["fc00::", 7], // unique local
  ["fe80::", 10], // link-local
  ["ff00::", 8], // multicast
] as const) {
  blocked.addSubnet(net, prefix, "ipv6");
}

const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "metadata.google.internal",
  "metadata",
  "instance-data",
]);
const BLOCKED_SUFFIXES = [".localhost", ".local", ".internal", ".lan", ".home.arpa"];

/** Extract an embedded IPv4 from IPv4-mapped IPv6 (::ffff:a.b.c.d or ::ffff:hhhh:hhhh). */
function unmapIPv4(ip: string): string | null {
  const lower = ip.toLowerCase();
  const dotted = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (dotted) return dotted[1];
  const hex = lower.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (hex) {
    const hi = parseInt(hex[1], 16);
    const lo = parseInt(hex[2], 16);
    return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  }
  return null;
}

export function isBlockedIp(ip: string): boolean {
  const family = isIP(ip);
  if (family === 0) return true; // not an IP: treat as blocked
  if (family === 6) {
    const mapped = unmapIPv4(ip);
    if (mapped) return blocked.check(mapped, "ipv4");
    return blocked.check(ip, "ipv6");
  }
  return blocked.check(ip, "ipv4");
}

export interface ParsedTarget {
  url: URL;
  hostname: string;
}

/** Syntactic validation only (no DNS). */
export function parseTargetUrl(input: string): ParsedTarget {
  let raw = input.trim();
  if (!raw) throw new UnsafeUrlError("Enter a URL.", "empty");
  if (raw.length > 2048) throw new UnsafeUrlError("URL is too long.", "too_long");
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) raw = `https://${raw}`;

  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new UnsafeUrlError("That does not look like a valid URL.", "invalid");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new UnsafeUrlError("Only http:// and https:// URLs are supported.", "protocol");
  }
  if (url.username || url.password) {
    throw new UnsafeUrlError("URLs with embedded credentials are not allowed.", "credentials");
  }
  if (url.port && !["80", "443", "8080", "8443"].includes(url.port)) {
    throw new UnsafeUrlError("Only ports 80, 443, 8080 and 8443 are allowed.", "port");
  }

  // URL.hostname keeps brackets for IPv6 literals.
  const hostname = url.hostname.replace(/^\[|\]$/g, "").toLowerCase().replace(/\.$/, "");
  if (BLOCKED_HOSTNAMES.has(hostname) || BLOCKED_SUFFIXES.some((s) => hostname.endsWith(s))) {
    throw new UnsafeUrlError("Internal hostnames are not allowed.", "internal_host");
  }
  if (isIP(hostname) && isBlockedIp(hostname)) {
    throw new UnsafeUrlError("Private or reserved IP addresses are not allowed.", "private_ip");
  }
  if (!isIP(hostname) && !hostname.includes(".")) {
    throw new UnsafeUrlError("Enter a full domain name such as example.com.", "no_tld");
  }
  return { url, hostname };
}

export type Resolver = (hostname: string) => Promise<string[]>;

const defaultResolver: Resolver = async (hostname) => {
  const results = await lookup(hostname, { all: true, verbatim: true });
  return results.map((r) => r.address);
};

/**
 * Full validation: syntax + DNS. Every resolved address must be public.
 * Returns the validated IPs so callers can pin the connection to them.
 */
export async function assertSafeUrl(
  input: string,
  resolver: Resolver = defaultResolver,
): Promise<{ url: URL; addresses: string[] }> {
  const { url, hostname } = parseTargetUrl(input);
  if (isIP(hostname)) return { url, addresses: [hostname] };

  let addresses: string[];
  try {
    addresses = await resolver(hostname);
  } catch {
    throw new UnsafeUrlError(`Could not resolve ${hostname}.`, "dns_failure");
  }
  if (addresses.length === 0) {
    throw new UnsafeUrlError(`Could not resolve ${hostname}.`, "dns_failure");
  }
  for (const addr of addresses) {
    if (isBlockedIp(addr)) {
      throw new UnsafeUrlError(
        "This hostname resolves to a private or reserved address and cannot be fetched.",
        "private_resolution",
      );
    }
  }
  return { url, addresses };
}
