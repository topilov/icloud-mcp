/** Only these explicitly listed values may enter the container environment. */
export interface Settings {
  MCP_AUTH_TOKEN?: string;
  ICLOUD_EMAIL?: string;
  ICLOUD_APP_SPECIFIC_PASSWORD?: string;
  DEFAULT_TIMEZONE?: string;
  EMAIL_SEND_ALLOWLIST?: string;
}

// Keep exact names here so a future expansion of "safe-mail" cannot expand access.
export const MAIL_TOOLS = [
  "email_list_folders",
  "email_list_messages",
  "email_search",
  "email_get_message",
  "email_get_messages",
  "email_get_attachment",
  "email_send",
  "email_save_draft",
] as const;

export function hasToken(settings: Settings): boolean {
  return typeof settings.MCP_AUTH_TOKEN === "string" &&
    settings.MCP_AUTH_TOKEN.trim().length > 0;
}

export function containerEnvironment(settings: Settings): Record<string, string> {
  if (!hasToken(settings)) {
    throw new Error("MCP_AUTH_TOKEN is required");
  }
  const hasEmail = Boolean(settings.ICLOUD_EMAIL?.trim());
  const hasPassword = Boolean(settings.ICLOUD_APP_SPECIFIC_PASSWORD?.trim());
  if (hasEmail !== hasPassword) {
    throw new Error("Both mailbox secrets must be configured together");
  }
  return {
    MCP_AUTH_TOKEN: settings.MCP_AUTH_TOKEN!,
    MCP_TRANSPORT: "http",
    MCP_SERVER_HOST: "0.0.0.0",
    MCP_SERVER_PATH: "/mcp",
    PORT: "8000",
    ICLOUD_ENABLED_CATEGORIES: "email",
    ICLOUD_ENABLED_TOOLS: MAIL_TOOLS.join(","),
    ICLOUD_MCP_LOCAL_FILES: "false",
    ICLOUD_MCP_ALLOW_ENV_CREDENTIALS: hasEmail ? "true" : "false",
    DEFAULT_TIMEZONE: settings.DEFAULT_TIMEZONE || "UTC",
    EMAIL_SEND_ALLOWLIST: settings.EMAIL_SEND_ALLOWLIST || "",
    LOG_LEVEL: "WARNING",
    PYTHONUNBUFFERED: "1",
    ...(hasEmail ? {
      ICLOUD_EMAIL: settings.ICLOUD_EMAIL!,
      ICLOUD_APP_SPECIFIC_PASSWORD: settings.ICLOUD_APP_SPECIFIC_PASSWORD!,
    } : {}),
  };
}
