import tls from "node:tls";
import type { PeerCertificate } from "node:tls";
import { isIP } from "node:net";
import { assertSafeUrl, parseTargetUrl } from "../security/url-guard.ts";

export interface CertInfo {
  host: string;
  port: number;
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  daysRemaining: number;
  serial: string;
  fingerprint: string;
  san: string[];
  protocol: string | null;
  cipher: string | null;
  alpn: string | null;
  trusted: boolean;
  trustError: string | null;
}

interface RawCert {
  cert: PeerCertificate;
  protocol: string | null;
  cipher: string | null;
  alpn: string | null;
  authorized: boolean;
  authorizationError: string | null;
}

function connectOnce(address: string, port: number, servername: string | undefined, verify: boolean): Promise<RawCert> {
  return new Promise<RawCert>((resolve, reject) => {
    let settled = false;
    const socket = tls.connect(
      {
        host: address,
        port,
        servername,
        rejectUnauthorized: verify,
        timeout: 10_000,
        ALPNProtocols: ["h2", "http/1.1"],
      },
      () => {
        const cert = socket.getPeerCertificate(true);
        settled = true;
        resolve({
          cert,
          protocol: socket.getProtocol(),
          cipher: socket.getCipher()?.name ?? null,
          alpn: socket.alpnProtocol || null,
          authorized: socket.authorized,
          authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
        });
        socket.end();
      },
    );
    socket.on("timeout", () => {
      socket.destroy();
      if (!settled) { settled = true; reject(new Error("TLS handshake timed out.")); }
    });
    socket.on("error", (e) => {
      if (!settled) { settled = true; reject(e); }
    });
  });
}

/**
 * Connect to a public host and read its certificate.
 * A verified handshake is attempted first; if the chain is not trusted we
 * reconnect without verification purely to read and report the certificate.
 */
export async function inspectCertificate(input: string, port?: number): Promise<CertInfo> {
  const { url, hostname } = parseTargetUrl(input);
  const p = port ?? Number(url.port || 443);
  if (![443, 8443].includes(p)) throw new Error("Only ports 443 and 8443 are supported for TLS inspection.");

  // Resolve and validate first, then pin the socket to that address.
  const { addresses } = await assertSafeUrl(input);
  const servername = isIP(hostname) ? undefined : hostname;

  let raw: RawCert;
  let trusted = true;
  let trustError: string | null = null;
  try {
    raw = await connectOnce(addresses[0], p, servername, true);
  } catch (e) {
    trusted = false;
    trustError = (e as Error).message;
    raw = await connectOnce(addresses[0], p, servername, false);
  }

  const c = raw.cert;
  if (!c || !c.valid_to) throw new Error("The server did not present a TLS certificate.");

  const days = Math.floor((Date.parse(c.valid_to) - Date.now()) / 86_400_000);
  return {
    host: hostname,
    port: p,
    subject: c.subject?.CN ?? "",
    issuer: c.issuer?.O ?? c.issuer?.CN ?? "",
    validFrom: new Date(c.valid_from).toISOString(),
    validTo: new Date(c.valid_to).toISOString(),
    daysRemaining: Number.isFinite(days) ? days : 0,
    serial: c.serialNumber ?? "",
    fingerprint: c.fingerprint256 ?? "",
    san: (c.subjectaltname ?? "").split(/,\s*/).map((s) => s.replace(/^DNS:/, "")).filter(Boolean),
    protocol: raw.protocol,
    cipher: raw.cipher,
    alpn: raw.alpn,
    trusted,
    trustError,
  };
}
