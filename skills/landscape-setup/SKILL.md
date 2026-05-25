---
name: landscape-setup
description: |
  Set up authentication for the Landscape Router MCP server. Use this skill whenever the user
  needs to configure or reconfigure their Landscape router connection, when they mention
  "setup router", "配置路由器", "connect to landscape", "router login", "MCP token expired",
  or when MCP tools return authentication errors. This skill MUST be used before any other
  landscape skill.
---

# Landscape Router Setup

Authenticate with a Landscape Router and obtain a JWT token so that landscape MCP tools
can be used from the current agent.

**Important: This skill and all other landscape skills ONLY work through MCP tools.
Do NOT call the Landscape REST API directly (e.g. via curl or HTTP requests) to query
data. If the MCP server is not configured yet, tell the user to configure it first.
Without MCP configured, the skill is not usable.**

## When to trigger

Run this skill when:
- The user asks to set up a Landscape router connection
- Other landscape skills fail due to missing or expired token
- The user says "setup", "login", "connect", "auth" in reference to landscape/router
- Token file is missing or expired

## Workflow

### Step 1: Check existing token and MCP server

Read `~/.agents/skills/landscape-setup/.token` if it exists. Parse the JSON:
- `host`: router base URL
- `token`: JWT Bearer token
- `exp`: expiry timestamp (unix seconds)

Then determine the next step:
- If token is expired → skip to Step 3 (re-login, defaulting the host from `.token`).
- If token is valid but the landscape MCP server is not configured in the current agent → skip to Step 4 (configure MCP).
- If token is valid and the MCP server is already configured → skip to Step 5 (verify).

### Step 2: Gather credentials

Ask the user for:
1. **Router address** — the full base URL including protocol and port, e.g. `https://192.168.5.185:6443`
2. **Username** — web UI login username
3. **Password** — web UI login password

Default to the `host` value from an existing `.token` file if re-authenticating.

### Step 3: Login

Run the bundled login script:

```bash
bash ~/.agents/skills/landscape-setup/scripts/login.sh \
  --host "THE_HOST" \
  --user "THE_USER" \
  --pass "THE_PASS"
```

The script:
- POSTs to `/api/auth/login` with credentials
- Extracts the JWT token
- Decodes the expiry timestamp
- Saves `host`, `token`, `exp` to `~/.agents/skills/landscape-setup/.token`
- **Important:** After updating the .token file, remind the user that update Authorization of mcp config.

### Step 4: Configure MCP

You now have:
- MCP endpoint: `THE_HOST/mcp`
- Authorization header: `Bearer THE_TOKEN`

This server uses an API key (Bearer JWT token), **not OAuth**. Disable OAuth auto-detection
for this server if your agent platform requires it.

Configure the landscape MCP server in the current agent. Use whatever configuration
mechanism the agent platform provides (MCP server config file, `/mcp` command, settings UI, etc.).

**If you are unsure how to configure an MCP server on the current agent platform,
stop here and tell the user to configure it manually.** Do not attempt to guess,
modify random config files, or write configuration examples. Simply tell the user:
"Please add a remote MCP server named `landscape` with URL `THE_HOST/mcp` and
header `Authorization: Bearer THE_TOKEN` to your MCP configuration, then restart
the agent."


### Step 5: Verify connection

Once the MCP server is configured and loaded, verify by calling:

```
landscape_system_info
```

If it returns system information (hostname, kernel version, etc.), setup is complete.

If it fails with an auth error:
- The token may have expired — re-run from Step 2
- The host URL may be wrong — double-check and re-run from Step 3
- The MCP client may need a restart/reload

### Step 6: Report success

Tell the user:
- What router they're connected to (hostname from `landscape_system_info`)
- When the token expires (from `.token` file)
- That other landscape skills (`landscape-health-check`, `landscape-troubleshoot-connection`, etc.) are now usable
