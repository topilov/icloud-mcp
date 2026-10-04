# Cloudflare Containers deployment preparation

This is a **single-user, mail-only deployment configuration**, not a deployed
service. No account, credentials, OAuth application, image, or plugin connection
is created by the tests or build scripts. The default bearer endpoint is useful
for infrastructure checks; it is **not by itself a dot/ChatGPT-ready plugin**.
OpenAI's [plugin authentication requirements](https://developers.openai.com/plugins/build/auth)
use OAuth for authenticated plugins and do not support a custom API-key login.

## Architecture and security boundaries

- One Worker routes only HTTPS `/mcp` to the fixed container name
  `icloud-mail-singleton`. Other paths, including public `/health`, return 404.
- Only authenticated POST requests are forwarded. GET, DELETE, and other
  methods return 405 with `Allow: POST` without container lookup. This stateless
  MCP service needs no persistent session or idle server-push GET/SSE channel,
  which could otherwise keep the container running. POST responses may stream.
- `max_instances: 1`, `instance_type: lite`, and `sleepAfter: 60s` keep the
  deployment small. There is no cron, warm-up ping, autoscaling, or keepalive job.
  The short idle timeout trades faster scale-to-zero for additional cold starts.
- The container listens on port 8000 and runs `icloud-mcp --http`. The Python
  middleware independently requires `MCP_AUTH_TOKEN`; HTTP never permits local
  attachment-file access. Internet access is enabled for iCloud IMAP/SMTP.
- Runtime configuration enables category `email` and **exactly** these tools:
  `email_list_folders`, `email_list_messages`, `email_search`,
  `email_get_message`, `email_get_messages`, `email_get_attachment`,
  `email_send`, `email_save_draft`. Deletion, moving, read-flag changes, calendar,
  and contacts are excluded. Sending and drafting remain real write actions.
- `EMAIL_SEND_ALLOWLIST` can additionally restrict recipients. When unset,
  allowed sending tools can send to arbitrary recipients. Select the desired
  restriction before real use; the tool profile alone is not a recipient policy.
- Rejected edge requests never obtain a container stub. Responses are marked
  `no-store`; streams are forwarded without buffering. Backend failures are
  generic and never automatically retried, to avoid duplicate sends.
- Caller-supplied `cf-container-target-port` is removed in both auth modes,
  and the container override explicitly targets port 8000. External requests
  cannot select another port through the Containers SDK.
- An `Origin` header must exactly match the endpoint's origin; foreign, empty,
  or `null` origins receive 403 before container lookup. Server-to-server clients
  may omit Origin. Cross-origin browser access/CORS is not supported.
- Preview URLs and Worker observability are disabled. Application code never
  logs request URLs, headers, payloads, identities, or secrets. Review any
  account-wide logging separately before mailbox use.
- `.dockerignore` excludes env files, `.dev.vars*`, Wrangler/Cloudflare state,
  Node modules, Worker config, and build artifacts. Never add secrets as Docker
  build arguments, plaintext Wrangler vars, source files, or CI build variables.

The implementation follows Cloudflare's
[Container class API](https://developers.cloudflare.com/containers/api/container-class/)
with the default scheduling policy and SQLite Durable Object storage. Keep the
container name, binding, and class stable on subsequent deployments.

## Authentication modes

### Bearer: infrastructure checks only

`AUTH_MODE=bearer` is checked in. A nonblank Worker secret `MCP_AUTH_TOKEN` is
required. Missing configuration returns 503 without starting the container.
Use `Authorization: Bearer <token>` or `X-MCP-Token: <token>` over HTTPS. The
comparison uses SHA-256 hashes and Cloudflare's constant-time comparison.
Python checks the same secret again. Tokens in query strings are not accepted.

Without optional mailbox secrets, no Apple login occurs during startup or
MCP `initialize` / `tools/list`. Mail operations require the client's explicit
Apple headers, or Basic authentication together with `X-MCP-Token`. Clients
must never send an Apple account password; only an app-specific password works.

### Access: optional platform-authenticated front door

The prepared `AUTH_MODE=access` path requires all of:

1. A real Cloudflare Access application protecting the deployed hostname,
   configured with **Managed OAuth** and an allow policy for the intended user
2. `ACCESS_AUD` set to that application's exact audience tag
3. `ACCESS_ALLOWED_EMAIL` set to the single intended login identity
4. The internal `MCP_AUTH_TOKEN` secret, plus paired mailbox runtime secrets
   before any real mail operation

Change the mode in the checked-in Wrangler `vars` for the approved deployment;
do not merely add an Access app while leaving this Worker in bearer mode. Keep
audience and identity settings in the deployment configuration or Worker
secrets; values are intentionally absent here. An unknown mode fails closed.

The Worker trusts only Cloudflare's `ctx.access` for a **directly authenticated
Worker invocation**, then requires the exact audience and allowed email. Raw
`Cf-Access-Jwt-Assertion` and identity headers cannot authenticate a request.
Cloudflare handles token signature, expiry, issuer, OAuth discovery, and refresh;
this Worker does not implement an OAuth server or parse unverified JWT claims.
This supported boundary is described in
[Workers Access identity documentation](https://developers.cloudflare.com/workers/configuration/cloudflare-access/#read-authenticated-user-identity-with-ctxaccess).

Only after authorization does the Worker remove external authorization, cookies,
Access assertions/service-token headers, and Apple credential headers. It sets
the internal `X-MCP-Token` before forwarding. No bearer fallback is available in
Access mode, and client input cannot select a different mailbox.

Use a dedicated hostname-based self-hosted Access app if appropriate; protect
the whole hostname so Access handles its discovery paths. Enable
[Managed OAuth](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/)
and obtain the exact redirect URI from the actual plugin setup flow. Do not
guess a callback or allow broad wildcards. This requires explicit account and
permission approval; no Access resource has been configured by this patch.

**Release gate:** the real Managed OAuth flow has not been tested. Verify that
Cloudflare supplies `ctx.access` for this deployment's opaque OAuth-token
requests, discovery works, the intended user connects, and another user is
rejected. Missing context fails closed. Service-binding calls and assets-router
invocations do not carry this context; do not add either in front of this Worker
without redesigning and revalidating authentication.

## Preparation without credentials or deployment

Use Node 22.18+ (tested on Node 24), Python 3.11+, and the committed lockfile:

```sh
npm ci
npm run check
npm run build:worker
python -m pytest -q
ruff check src tests
```

`build:worker` runs `wrangler deploy --dry-run --containers-rollout=none`.
It validates and bundles the Worker without uploading, logging in, creating
credentials, or building the Docker image. It is **not an image or deployment
test**. A full dry run with the Dockerfile requires a running Docker-compatible
engine. Node unit tests substitute Node's constant-time primitive for the
Workers-only WebCrypto extension and mock container routing/Access context.

For a Docker-capable cloud environment, an approved full local build/test can
use `docker build --platform linux/amd64 -t icloud-mcp:review .`. Run the image
with a disposable test token and no mailbox credentials, verify health,
unauthenticated 401, authenticated initialization, and the exact eight tools.
Do not treat a passing image build as permission to deploy it.

## Authorized cloud-only deployment path

Deployment, paid-plan activation, repository access grants, persistent access,
secret entry, and plugin authorization are separate approval steps. The commands
below are instructions for a later approved deployment, not actions run here.

1. Confirm the destination Cloudflare account, Worker name, billing approval,
   selected commit, and exact OAuth application configuration. Review the
   [current Containers pricing](https://developers.cloudflare.com/containers/platform/pricing/).
2. For a machine-free build, connect only the required GitHub repository to
   **Workers Builds**, subject to approval of the app's requested permissions.
   For the initial hardening rollout, the repository is `topilov/icloud-mcp`
   and the selected deployment/production branch must be
   `security/cloud-mail-hardening`, after this patch is published there and its
   exact commit is verified. Do not build unpatched `main`; no merge is implied.
   Keep repository root as build root; use `npm ci && npm run check` for the
   Worker checks and `npx wrangler deploy` as the authorized deployment command.
   Add the Python test setup to CI separately if desired.
   Approve the narrowly scoped repository app and any required build token
   separately; this preparation does not create or authorize either grant.
3. Workers Builds supports Dockerfile image builds. Default non-production
   `wrangler versions upload` does not build/roll out the container. Never change
   a production Worker's feature-branch command to full deploy merely to preview
   a PR. See [Cloudflare's deployment guide](https://developers.cloudflare.com/containers/guides/deploy/).
4. Enter a strong random internal token through the official Worker runtime
   secret interface. If CLI entry is used, `npx wrangler secret put MCP_AUTH_TOKEN`
   must be performed in a trusted authorized environment by the secret holder.
   Do not put the value in chat, a command argument, a Git file, or build logs.
   The first approved deployment can intentionally omit all runtime secrets:
   it will return 503 and cannot start an unauthenticated container. Establish
   the protected front door before entering mailbox credentials.
5. Optionally enter runtime secrets `ICLOUD_EMAIL` and
   `ICLOUD_APP_SPECIFIC_PASSWORD` together through that same secure flow.
   The container enables env fallback only when both are present; a partial pair
   refuses startup. Mailbox credentials are never required for preparation.
6. Complete the approved Access settings/mode change and deploy the selected
   commit. Confirm both Worker and image versions: deployment is not transactional,
   and Worker code can become live before an image build or rollout finishes.
7. Perform the release checks below before connecting real mail.
   Creating/authorizing the personal plugin is a separate user-controlled grant;
   start live validation with discovery and a read-only mailbox operation.

Alternatively, an explicitly approved cloud build host with Docker can run a
full `npx wrangler deploy`. A prebuilt `linux/amd64` registry image is another
supported route. None requires the user's Mac.

## Capacity, costs, and release checks

Cloudflare's [lite instance](https://developers.cloudflare.com/containers/platform/limits/)
has 256 MiB RAM, 1/16 vCPU, and 2 GB disk. In the preparation environment, the
actual Python CLI serving health, initialization, and `tools/list` used about
100.8 MiB RSS/high-water memory with no Apple credentials. This supports trying
lite for light use, not a guarantee: it was not measured inside the final image,
under Cloudflare's CPU quota, or with large messages/attachments/concurrency.

The paid Workers plan and usage charges apply. One instance plus idle sleep
reduces cost but is not a monetary spending cap. Frequent or long-lived requests
can keep it running; there are also Worker, Durable Object, build, registry,
network, and potentially account-wide logging charges. Start small and obtain
approval before switching to `basic` or extending the idle time.

Before saying the endpoint is usable:

- Verify image build and provisioning, HTTPS URL, cold-start latency, idle stop,
  and successful restart with the same singleton
- Verify missing/invalid authentication never starts a container; Access mode
  rejects a spoofed assertion and valid internal bearer when no Access identity
  exists; direct/alternate hostname routes must fail closed
- Complete real OAuth discovery/login/refresh and denied-user tests; unit-test
  contexts do not prove platform JWT validation or a working ChatGPT connection
- Verify exact eight-tool discovery and excluded tools unavailable; no mailbox
  writes are needed for this check
- With explicit mailbox authorization, verify IMAP 993 and SMTP 587 connectivity
  and a small read; obtain separate approval for sending/draft test content
- Observe memory/CPU with realistic read/attachment sizes before increasing
  workload; inline attachment data still consumes memory despite local files off
- Restart/drain the singleton after changing runtime secrets so the process gets
  the new environment. A rolling Worker change alone is not proof of rotation.
  Never retry an uncertain send until its outcome has been checked

The container filesystem is ephemeral. No mail state or durable attachment
cache is expected on disk. Any future persistence or additional tools need a
fresh security review.
