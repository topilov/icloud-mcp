import { hasToken, type Settings } from "./environment.ts";

export const CONTAINER_NAME = "icloud-mail-singleton";

export interface EdgeEnv extends Settings {
  AUTH_MODE?: string;
  ACCESS_AUD?: string;
  ACCESS_ALLOWED_EMAIL?: string;
  ICLOUD_MCP: {
    getByName(name: string): { fetch(request: Request): Promise<Response> };
  };
}

export type EdgeContext = Pick<ExecutionContext, "access">;

function response(status: number, error: string, extra: Record<string, string> = {}): Response {
  return Response.json({ error }, {
    status,
    headers: {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Strict-Transport-Security": "max-age=31536000",
      ...extra,
    },
  });
}

async function tokenMatches(provided: string, expected: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const [providedHash, expectedHash] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(provided)),
    crypto.subtle.digest("SHA-256", encoder.encode(expected)),
  ]);
  // Cloudflare's constant-time primitive; hashes keep both operands fixed size.
  return crypto.subtle.timingSafeEqual(providedHash, expectedHash);
}

export async function handleRequest(request: Request, env: EdgeEnv, ctx: EdgeContext = {}): Promise<Response> {
  const url = new URL(request.url);
  // Never redirect a request that might contain credentials over plaintext HTTP.
  if (url.protocol !== "https:") return response(400, "HTTPS required");
  if (url.pathname !== "/mcp") return response(404, "Not found");
  const origin = request.headers.get("Origin");
  if (origin !== null && origin !== url.origin) return response(403, "Origin not allowed");
  if (!hasToken(env)) return response(503, "Service not configured");

  const mode = env.AUTH_MODE ?? "bearer";
  let forwarded = request;
  if (mode === "access") {
    if (!env.ACCESS_AUD?.trim() || !env.ACCESS_ALLOWED_EMAIL?.trim()) {
      return response(503, "Service not configured");
    }
    // Trust only Cloudflare's authenticated invocation context, never a caller's
    // Cf-Access-Jwt-Assertion or identity header. Access validates JWTs/OAuth.
    if (!ctx.access || ctx.access.aud !== env.ACCESS_AUD) return response(403, "Access required");
    try {
      const identity = await ctx.access.getIdentity();
      if (!identity?.email || identity.email.toLowerCase() !== env.ACCESS_ALLOWED_EMAIL.trim().toLowerCase()) {
        return response(403, "Access denied");
      }
    } catch {
      return response(503, "Identity unavailable");
    }
    // Access mode is a single-user mailbox service. Client headers must not
    // select a different mailbox or leak OAuth/session secrets into the image.
    forwarded = new Request(request);
    for (const name of [
      "Authorization", "X-MCP-Token", "Cookie", "Cf-Access-Jwt-Assertion",
      "Cf-Access-Client-Id", "Cf-Access-Client-Secret", "Cf-Access-Authenticated-User-Email",
      "X-Apple-Email", "X-Apple-App-Specific-Password",
    ]) forwarded.headers.delete(name);
    forwarded.headers.set("X-MCP-Token", env.MCP_AUTH_TOKEN!);
  } else if (mode === "bearer") {
    // Match the Python middleware's precedence, including Basic + X-MCP-Token.
    const authorization = request.headers.get("Authorization") || "";
    const provided = request.headers.get("X-MCP-Token") ||
      (authorization.toLowerCase().startsWith("bearer ") ? authorization.slice(7).trim() : "");
    if (!provided || !(await tokenMatches(provided, env.MCP_AUTH_TOKEN!))) {
      return response(401, "Unauthorized", { "WWW-Authenticate": 'Bearer realm="icloud-mcp"' });
    }
  } else {
    // Typos or removed configuration must never silently fall back to bearer.
    return response(503, "Service not configured");
  }
  // Stateless MCP uses POST. An idle GET/SSE stream could keep a lite instance
  // running indefinitely; there is no persistent session for DELETE to close.
  if (request.method !== "POST") {
    return response(405, "Method not allowed", { Allow: "POST" });
  }
  if (request.headers.has("Upgrade")) return response(400, "Upgrade not supported");
  // The Containers SDK interprets this internal header as a port override.
  // Never let external callers select a port or trigger unrelated readiness waits.
  forwarded = new Request(forwarded);
  forwarded.headers.delete("cf-container-target-port");

  try {
    // No container lookup/start occurs until HTTPS, path and authentication pass.
    // A fixed name prevents callers from creating extra instances via path/header.
    const upstream = await env.ICLOUD_MCP.getByName(CONTAINER_NAME).fetch(forwarded);
    if (upstream.status >= 500) {
      await upstream.body?.cancel();
      return response(503, "Service temporarily unavailable");
    }
    const headers = new Headers(upstream.headers);
    headers.set("Cache-Control", "no-store");
    headers.set("X-Content-Type-Options", "nosniff");
    headers.set("Strict-Transport-Security", "max-age=31536000");
    return new Response(upstream.body, { status: upstream.status, statusText: upstream.statusText, headers });
  } catch {
    // Do not echo exception details or retry a possibly completed email_send.
    return response(503, "Service temporarily unavailable");
  }
}
