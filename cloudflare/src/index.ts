import { Container } from "@cloudflare/containers";
import { handleRequest, type EdgeEnv } from "./edge.ts";
import { containerEnvironment } from "./environment.ts";

interface Env extends EdgeEnv {
  ICLOUD_MCP: DurableObjectNamespace<IcloudMcpContainer>;
}

export class IcloudMcpContainer extends Container<Env> {
  defaultPort = 8000;
  sleepAfter = "60s";
  enableInternet = true;
  // Use the supported entrypoint, which installs Python authentication and forces
  // local filesystem access off. Never invoke FastMCP directly from this image.
  entrypoint = ["icloud-mcp", "--http"];
  envVars = containerEnvironment(this.env);

  override fetch(request: Request): Promise<Response> {
    // Defense in depth: bypass the SDK fetch() port-selection header entirely.
    return this.containerFetch(request, 8000);
  }

  override onError(_error: unknown): void {
    // The parent handler returns a generic 503. Never log credential-bearing errors.
    throw new Error("Container unavailable");
  }
}

export default {
  fetch: handleRequest,
} satisfies ExportedHandler<Env>;
