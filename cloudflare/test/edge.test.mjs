import assert from "node:assert/strict";
import { timingSafeEqual } from "node:crypto";
import { test } from "node:test";
import { handleRequest, CONTAINER_NAME } from "../src/edge.ts";

// Node lacks Cloudflare's WebCrypto extension. Use Node's same constant-time
// primitive for unit tests; the Worker build uses the native Workers extension.
crypto.subtle.timingSafeEqual = (a, b) => timingSafeEqual(new Uint8Array(a), new Uint8Array(b));
const token = "unit-test-placeholder-not-a-real-secret";
const auth = { Authorization: `Bearer ${token}` };

function fixture(overrides = {}, backend) {
  const calls = [];
  const names = [];
  const env = {
    MCP_AUTH_TOKEN: token,
    ICLOUD_MCP: { getByName(name) {
      names.push(name);
      return { async fetch(request) {
        calls.push(request);
        return backend ? backend(request) : new Response("data: result\n\n", {
          headers: { "Content-Type": "text/event-stream", "Mcp-Session-Id": "test-id" },
        });
      } };
    } },
    ...overrides,
  };
  return { env, calls, names };
}

for (const absent of [undefined, "", "   "]) {
  test(`missing/blank server token fails closed (${JSON.stringify(absent)})`, async () => {
    const f = fixture({ MCP_AUTH_TOKEN: absent });
    const res = await handleRequest(new Request("https://example.test/mcp", { headers: auth }), f.env);
    assert.equal(res.status, 503);
    assert.deepEqual(f.names, []);
  });
}

for (const headers of [{}, { Authorization: "Bearer wrong" }, { "X-MCP-Token": "wrong" },
  { Authorization: "Basic dGVzdDp0ZXN0" }, { Authorization: `Bearer ${token}`, "X-MCP-Token": "wrong" }]) {
  test(`unauthenticated request never obtains a container: ${JSON.stringify(headers)}`, async () => {
    const f = fixture();
    const res = await handleRequest(new Request("https://example.test/mcp", { headers }), f.env);
    assert.equal(res.status, 401);
    assert.match(res.headers.get("WWW-Authenticate"), /^Bearer/);
    assert.deepEqual(f.names, []);
    assert.equal(res.headers.get("Cache-Control"), "no-store");
  });
}

for (const url of ["http://example.test/mcp", "https://example.test/health", "https://example.test/mcp/",
  "https://example.test/", "https://example.test/mcp/another-instance"]) {
  test(`only exact HTTPS endpoint routes: ${url}`, async () => {
    const f = fixture();
    const res = await handleRequest(new Request(url, { headers: auth }), f.env);
    assert.equal(res.status, url.startsWith("http:") ? 400 : 404);
    assert.equal(res.headers.has("Location"), false);
    assert.deepEqual(f.names, []);
  });
}

test("query token does not authenticate", async () => {
  const f = fixture();
  const res = await handleRequest(new Request(`https://example.test/mcp?token=${token}`), f.env);
  assert.equal(res.status, 401);
  assert.deepEqual(f.names, []);
});

for (const method of ["POST"]) {
  test(`${method} preserves streaming response and always uses singleton`, async () => {
    const f = fixture();
    const request = new Request("https://example.test/mcp", { method, headers: auth,
      ...(method === "POST" ? { body: '{"jsonrpc":"2.0","method":"tools/list","id":1}' } : {}) });
    const res = await handleRequest(request, f.env);
    assert.equal(res.status, 200);
    assert.equal(await res.text(), "data: result\n\n");
    assert.equal(res.headers.get("Mcp-Session-Id"), "test-id");
    assert.equal(res.headers.get("Content-Type"), "text/event-stream");
    assert.equal(res.headers.get("Cache-Control"), "no-store");
    assert.deepEqual(f.names, [CONTAINER_NAME]);
    assert.equal(f.calls[0].url, request.url);
    assert.equal(f.calls[0].method, request.method);
    assert.equal(f.calls[0].headers.get("Authorization"), auth.Authorization);
  });
}

for (const headers of [{ "X-MCP-Token": token }, { Authorization: `bEaReR ${token}` },
  { Authorization: "Basic dGVzdDp0ZXN0", "X-MCP-Token": token }]) {
  test("both token mechanisms match Python precedence", async () => {
    const f = fixture();
    const res = await handleRequest(new Request("https://example.test/mcp", { method: "POST", headers }), f.env);
    assert.equal(res.status, 200);
    assert.equal(f.calls[0].headers.get("Authorization"), headers.Authorization || null);
  });
}

for (const method of ["OPTIONS", "PUT", "HEAD", "GET", "DELETE"]) {
  test(`${method} is rejected without container invocation`, async () => {
    const f = fixture();
    const res = await handleRequest(new Request("https://example.test/mcp", { method, headers: auth }), f.env);
    assert.equal(res.status, 405);
    assert.equal(res.headers.get("Allow"), "POST");
    assert.deepEqual(f.names, []);
  });
}

test("backend failure is generic and never retried", async () => {
  const f = fixture({}, () => { throw new Error("private backend details and credentials"); });
  const res = await handleRequest(new Request("https://example.test/mcp", { method: "POST", headers: auth }), f.env);
  assert.equal(res.status, 503);
  assert.doesNotMatch(await res.text(), /private|credentials/);
  assert.equal(f.calls.length, 1);
});

test("backend 500 diagnostics are discarded", async () => {
  const f = fixture({}, () => new Response("private startup error", { status: 500 }));
  const res = await handleRequest(new Request("https://example.test/mcp", { method: "POST", headers: auth }), f.env);
  assert.equal(res.status, 503);
  assert.doesNotMatch(await res.text(), /private/);
});

const accessSettings = { AUTH_MODE: "access", ACCESS_AUD: "test-audience", ACCESS_ALLOWED_EMAIL: "owner@example.test" };
const context = { access: { aud: "test-audience", async getIdentity() { return { email: "owner@example.test" }; } } };

for (const mode of ["bearer", "access"]) {
  for (const origin of [undefined, "https://example.test", "https://other.test", "null", ""]) {
    test(`${mode} validates browser Origin (${JSON.stringify(origin)})`, async () => {
      const f = fixture(mode === "access" ? accessSettings : {});
      const headers = { ...auth, ...(origin === undefined ? {} : { Origin: origin }) };
      const res = await handleRequest(new Request("https://example.test/mcp", { method: "POST", headers }), f.env, context);
      const accepted = origin === undefined || origin === "https://example.test";
      assert.equal(res.status, accepted ? 200 : 403);
      assert.equal(f.names.length, accepted ? 1 : 0);
      assert.equal(res.headers.has("Access-Control-Allow-Origin"), false);
    });
  }
}

for (const mode of ["bearer", "access"]) {
  test(`${mode} strips the SDK port override header`, async () => {
    const f = fixture(mode === "access" ? accessSettings : {});
    const req = new Request("https://example.test/mcp", { method: "POST", headers: { ...auth, "cf-container-target-port": "22" } });
    const res = await handleRequest(req, f.env, context);
    assert.equal(res.status, 200);
    assert.equal(f.calls[0].headers.has("cf-container-target-port"), false);
    assert.equal(req.headers.get("cf-container-target-port"), "22");
  });
}

for (const overrides of [{ AUTH_MODE: "typo" }, { ...accessSettings, ACCESS_AUD: "" },
  { ...accessSettings, ACCESS_ALLOWED_EMAIL: "" }]) {
  test("unknown auth mode or incomplete Access settings fail closed", async () => {
    const f = fixture(overrides);
    const res = await handleRequest(new Request("https://example.test/mcp", { headers: auth }), f.env, context);
    assert.equal(res.status, 503);
    assert.deepEqual(f.names, []);
  });
}

test("spoofed JWT and valid internal bearer cannot bypass Access context", async () => {
  const f = fixture(accessSettings);
  const res = await handleRequest(new Request("https://example.test/mcp", { headers: {
    ...auth, "Cf-Access-Jwt-Assertion": "attacker-controlled", "Cf-Access-Authenticated-User-Email": "owner@example.test",
  } }), f.env);
  assert.equal(res.status, 403);
  assert.deepEqual(f.names, []);
});

for (const access of [
  { aud: "wrong", getIdentity: context.access.getIdentity },
  { aud: "test-audience", async getIdentity() { return undefined; } },
  { aud: "test-audience", async getIdentity() { return {}; } },
  { aud: "test-audience", async getIdentity() { return { email: "intruder@example.test" }; } },
]) {
  test("wrong audience, missing identity, or disallowed email never routes", async () => {
    const f = fixture(accessSettings);
    const res = await handleRequest(new Request("https://example.test/mcp", { headers: auth }), f.env, { access });
    assert.equal(res.status, 403);
    assert.deepEqual(f.names, []);
  });
}

test("Access identity lookup failure never routes or echoes details", async () => {
  const f = fixture(accessSettings);
  const access = { aud: "test-audience", async getIdentity() { throw new Error("private error"); } };
  const res = await handleRequest(new Request("https://example.test/mcp"), f.env, { access });
  assert.equal(res.status, 503);
  assert.doesNotMatch(await res.text(), /private/);
  assert.deepEqual(f.names, []);
});

test("Access permits only trusted identity and rewrites sensitive headers", async () => {
  const f = fixture(accessSettings);
  const headers = {
    Authorization: "Bearer external-oauth-placeholder", "X-MCP-Token": "attacker-token",
    Cookie: "CF_Authorization=placeholder", "Cf-Access-Jwt-Assertion": "assertion-placeholder",
    "Cf-Access-Client-Id": "id-placeholder", "Cf-Access-Client-Secret": "secret-placeholder",
    "Cf-Access-Authenticated-User-Email": "spoofed@example.test",
    "X-Apple-Email": "spoofed@example.test", "X-Apple-App-Specific-Password": "spoofed-password",
    "Content-Type": "application/json", Accept: "application/json,text/event-stream", "MCP-Protocol-Version": "2025-03-26",
  };
  const request = new Request("https://example.test/mcp", { method: "POST", headers, body: '{"id":1}' });
  const res = await handleRequest(request, f.env, context);
  assert.equal(res.status, 200);
  assert.deepEqual(f.names, [CONTAINER_NAME]);
  const sent = f.calls[0];
  for (const header of Object.keys(headers).filter(name => !["X-MCP-Token", "Content-Type", "Accept", "MCP-Protocol-Version"].includes(name))) {
    assert.equal(sent.headers.has(header), false, header);
  }
  assert.equal(sent.headers.get("X-MCP-Token"), token);
  assert.equal(sent.headers.get("MCP-Protocol-Version"), "2025-03-26");
  assert.equal(await sent.text(), '{"id":1}');
  assert.equal(request.headers.get("Authorization"), headers.Authorization);
});
