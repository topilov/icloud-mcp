import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { containerEnvironment, MAIL_TOOLS } from "../src/environment.ts";

const token = "test-only-placeholder";
const root = new URL("../../", import.meta.url);
const read = path => readFileSync(new URL(path, root), "utf8");

test("container always has exact safe-mail surface and HTTP security defaults", () => {
  const env = containerEnvironment({ MCP_AUTH_TOKEN: token, ICLOUD_ENABLED_TOOLS: "all", ICLOUD_MCP_LOCAL_FILES: "true" });
  assert.deepEqual(MAIL_TOOLS, ["email_list_folders", "email_list_messages", "email_search", "email_get_message",
    "email_get_messages", "email_get_attachment", "email_send", "email_save_draft"]);
  assert.equal(env.ICLOUD_ENABLED_TOOLS, MAIL_TOOLS.join(","));
  assert.equal(env.ICLOUD_ENABLED_CATEGORIES, "email");
  assert.equal(env.ICLOUD_MCP_LOCAL_FILES, "false");
  assert.equal(env.ICLOUD_MCP_ALLOW_ENV_CREDENTIALS, "false");
  assert.equal(env.MCP_AUTH_TOKEN, token);
  assert.equal(env.MCP_TRANSPORT, "http");
  assert.equal(env.MCP_SERVER_HOST, "0.0.0.0");
  assert.equal(env.MCP_SERVER_PATH, "/mcp");
  assert.equal(env.PORT, "8000");
  assert.equal(env.DEFAULT_TIMEZONE, "UTC");
  assert.equal("ICLOUD_EMAIL" in env, false);
  assert.equal("ICLOUD_APP_SPECIFIC_PASSWORD" in env, false);
});

test("only explicit optional settings and paired mailbox secrets pass through", () => {
  const env = containerEnvironment({ MCP_AUTH_TOKEN: token, ICLOUD_EMAIL: "dummy@example.test",
    ICLOUD_APP_SPECIFIC_PASSWORD: "dummy-password", EMAIL_SEND_ALLOWLIST: "approved@example.test",
    DEFAULT_TIMEZONE: "Europe/London", CF_API_TOKEN: "must-not-pass" });
  assert.equal(env.ICLOUD_EMAIL, "dummy@example.test");
  assert.equal(env.ICLOUD_APP_SPECIFIC_PASSWORD, "dummy-password");
  assert.equal(env.ICLOUD_MCP_ALLOW_ENV_CREDENTIALS, "true");
  assert.equal(env.EMAIL_SEND_ALLOWLIST, "approved@example.test");
  assert.equal(env.DEFAULT_TIMEZONE, "Europe/London");
  assert.equal("CF_API_TOKEN" in env, false);
});

for (const settings of [{}, { MCP_AUTH_TOKEN: "" }, { MCP_AUTH_TOKEN: "  " },
  { MCP_AUTH_TOKEN: token, ICLOUD_EMAIL: "dummy@example.test" },
  { MCP_AUTH_TOKEN: token, ICLOUD_APP_SPECIFIC_PASSWORD: "dummy-password" }]) {
  test("missing authentication or unpaired mailbox secrets refuse startup", () => {
    assert.throws(() => containerEnvironment(settings));
  });
}

test("deployment is capped and uses supported HTTP entrypoint", () => {
  const config = JSON.parse(read("wrangler.jsonc").replace(/^\s*\/\/.*$/gm, ""));
  assert.equal(config.containers.length, 1);
  assert.equal(config.containers[0].max_instances, 1);
  assert.equal(config.containers[0].instance_type, "lite");
  assert.equal(config.containers[0].image, "./Dockerfile");
  assert.equal(config.preview_urls, false);
  assert.equal(config.observability.enabled, false);
  assert.equal(config.vars.AUTH_MODE, "bearer");
  assert.equal("MCP_AUTH_TOKEN" in config.vars, false);
  assert.equal(config.exports.IcloudMcpContainer.storage, "sqlite");
  const source = read("cloudflare/src/index.ts");
  assert.match(source, /sleepAfter = "60s"/);
  assert.match(source, /enableInternet = true/);
  assert.match(source, /entrypoint = \["icloud-mcp", "--http"\]/);
  assert.match(source, /override fetch\(request: Request\): Promise<Response>/);
  assert.match(source, /return this\.containerFetch\(request, 8000\)/);
  assert.match(read("Dockerfile"), /CMD \["icloud-mcp", "--http"\]/);
});

test("Docker and Git ignore local secrets, node dependencies and build outputs", () => {
  for (const path of [".dockerignore", ".gitignore"]) {
    const rules = read(path).split(/\r?\n/);
    for (const expected of [".env", ".env.*", ".dev.vars*", ".wrangler/", ".cloudflare/", "node_modules/", ".artifacts/", "artifacts/"]) {
      assert.ok(rules.includes(expected), `${path}: ${expected}`);
    }
  }
  for (const expected of ["cloudflare/", "wrangler*.json*", "wrangler*.toml", "package*.json"]) {
    assert.ok(read(".dockerignore").split(/\r?\n/).includes(expected));
  }
});
