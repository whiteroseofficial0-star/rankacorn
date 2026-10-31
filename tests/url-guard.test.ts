import { test } from "node:test";
import assert from "node:assert/strict";
import {
  assertSafeUrl,
  isBlockedIp,
  parseTargetUrl,
  UnsafeUrlError,
} from "../src/lib/security/url-guard.ts";

const publicResolver = async () => ["93.184.216.34"];

test("blocks private, loopback, link-local and metadata IPv4", () => {
  for (const ip of [
    "127.0.0.1",
    "10.1.2.3",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.1.1",
    "169.254.169.254",
    "100.64.0.1",
    "0.0.0.0",
    "224.0.0.1",
  ]) {
    assert.equal(isBlockedIp(ip), true, ip);
  }
});

test("allows public IPv4", () => {
  for (const ip of ["8.8.8.8", "93.184.216.34", "172.32.0.1", "1.1.1.1"]) {
    assert.equal(isBlockedIp(ip), false, ip);
  }
});

test("blocks IPv6 loopback, ULA, link-local and mapped private IPv4", () => {
  for (const ip of ["::1", "fc00::1", "fd12:3456::1", "fe80::1", "::ffff:127.0.0.1", "::ffff:7f00:1", "::ffff:169.254.169.254"]) {
    assert.equal(isBlockedIp(ip), true, ip);
  }
  assert.equal(isBlockedIp("2606:4700:4700::1111"), false);
});

test("rejects non-http protocols, credentials, odd ports", () => {
  for (const u of ["file:///etc/passwd", "ftp://example.com", "gopher://example.com", "javascript:alert(1)"]) {
    assert.throws(() => parseTargetUrl(u), UnsafeUrlError, u);
  }
  assert.throws(() => parseTargetUrl("https://user:pw@example.com"), UnsafeUrlError);
  assert.throws(() => parseTargetUrl("https://example.com:22"), UnsafeUrlError);
});

test("rejects internal hostnames and IP literals, including encoded forms", () => {
  for (const u of [
    "http://localhost",
    "http://foo.localhost",
    "http://metadata.google.internal",
    "http://127.0.0.1",
    "http://[::1]/",
    "http://2130706433/", // decimal 127.0.0.1, normalised by URL parser
    "http://0x7f.0.0.1/",
    "http://169.254.169.254/latest/meta-data",
    "http://intranet",
  ]) {
    assert.throws(() => parseTargetUrl(u), UnsafeUrlError, u);
  }
});

test("adds https:// when scheme is missing", () => {
  assert.equal(parseTargetUrl("example.com/page").url.href, "https://example.com/page");
});

test("DNS resolution to a private address is rejected", async () => {
  await assert.rejects(
    assertSafeUrl("https://evil.example.com", async () => ["10.0.0.5"]),
    (e: unknown) => e instanceof UnsafeUrlError && e.code === "private_resolution",
  );
  // any single bad record among several is enough to reject (DNS rebinding mix)
  await assert.rejects(
    assertSafeUrl("https://mixed.example.com", async () => ["93.184.216.34", "127.0.0.1"]),
    UnsafeUrlError,
  );
});

test("public resolution passes and returns addresses", async () => {
  const r = await assertSafeUrl("https://example.com", publicResolver);
  assert.deepEqual(r.addresses, ["93.184.216.34"]);
});

test("DNS failure yields a readable error", async () => {
  await assert.rejects(
    assertSafeUrl("https://nope.example.com", async () => {
      throw new Error("ENOTFOUND");
    }),
    (e: unknown) => e instanceof UnsafeUrlError && e.code === "dns_failure",
  );
});
