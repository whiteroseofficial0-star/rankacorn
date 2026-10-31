import { test } from "node:test";
import assert from "node:assert/strict";
import { safeFetch } from "../src/lib/security/safe-fetch.ts";
import { UnsafeUrlError } from "../src/lib/security/url-guard.ts";

test("refuses loopback targets before connecting", async () => {
  await assert.rejects(safeFetch("http://127.0.0.1:8080/"), UnsafeUrlError);
});

test("refuses hostnames that resolve to private space", async () => {
  await assert.rejects(
    safeFetch("https://example.com", { resolver: async () => ["192.168.0.10"] }),
    (e: unknown) => e instanceof UnsafeUrlError && e.code === "private_resolution",
  );
});

test("refuses cloud metadata endpoint", async () => {
  await assert.rejects(safeFetch("http://169.254.169.254/latest/meta-data/"), UnsafeUrlError);
});
