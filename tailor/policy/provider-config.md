# Provider configuration

The model provider is configuration only. Nothing in this fork holds a key, and no
key goes in a file in this repository, in `t3-policy.template.json`, or in a machine
environment variable. Credentials are entered once on the T3 Claude provider
instance (Settings, Providers, Claude, Environment) as **sensitive** values, or come
from the operating system's credential store (an AWS profile for Bedrock).

T3 drives Claude through the Claude Agent SDK and the Claude binary set as the
instance's `binaryPath`. Use the API-key or Bedrock path below. Never sign the
binary in with a personal Claude subscription: third-party products may not use
Claude.ai sign-in or plan limits.

## Option A: Anthropic API key

| Variable | Value |
| --- | --- |
| `ANTHROPIC_API_KEY` | the organisation's Console API key (sensitive; entered in T3, never written here) |
| `ANTHROPIC_BASE_URL` | optional. An organisation gateway that forwards the organisation's own key, for example `https://api.aukus.si`. Omit to use `https://api.anthropic.com`. |

If a gateway is used, add its host to `install-policy.ps1 -AllowedHosts`.

## Option B: Amazon Bedrock, Australian regions

| Variable | Value |
| --- | --- |
| `CLAUDE_CODE_USE_BEDROCK` | `1` |
| `AWS_REGION` | `ap-southeast-2` |
| `AWS_PROFILE` | optional: a named profile in the OS user's AWS config; credentials stay in the AWS credential store |

Bedrock serves the `au.` cross-region profile from Sydney (`ap-southeast-2`) and
Melbourne (`ap-southeast-4`), so both runtime endpoints are in the default egress
allowlist.

## Model pin

Pin the model on the instance so no request can fall back to a global profile.

| Variable | Bedrock value | API-key value |
| --- | --- | --- |
| `ANTHROPIC_MODEL` | `au.anthropic.claude-opus-5-5` | `claude-opus-5-5` |
| `ANTHROPIC_DEFAULT_OPUS_MODEL` | `au.anthropic.claude-opus-5-5` | `claude-opus-5-5` |
| `ANTHROPIC_DEFAULT_SONNET_MODEL` | `au.anthropic.claude-sonnet-5-5` | `claude-sonnet-5-5` |
| `ANTHROPIC_SMALL_FAST_MODEL` | `au.anthropic.claude-sonnet-5-5` | `claude-sonnet-5-5` |

Never use a `global.` or `us.` profile ID. A new model version may reach the `au.`
profile later than elsewhere; update the pin in a reviewed change, not at runtime.

## Always set on the instance

These keep the Claude binary quiet and fixed. They are set on the T3 provider
instance, not machine-wide, so other Claude installations on the machine are not
affected.

| Variable | Value |
| --- | --- |
| `DISABLE_AUTOUPDATER` | `1` |
| `DISABLE_TELEMETRY` | `1` |
| `DISABLE_ERROR_REPORTING` | `1` |
| `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` | `1` |
| `CLAUDE_CONFIG_DIR` | set by T3 from the instance's `homePath` (the policy's Claude config directory); do not set it by hand |

## Fixed by the build

The server opens every Claude query with no settings files (`settingSources: []`), only
T3's own MCP server, `WebSearch` and `WebFetch` disallowed, the permission mode capped at
Auto-accept edits, and compiled deny rules (tailor/policy/README.md). Repository
`CLAUDE.md` and `.claude/` files are not loaded. Instance launch arguments cannot raise the
permission mode.

## Other providers

The build contains the Claude driver only (`TAILOR_CLAUDE_ONLY` in
`apps/server/src/provider/builtInDrivers.ts`). Adding any other provider is a reviewed change
that also extends the policy and the egress allowlist.

## What the user-writable instance settings can no longer change

With the machine policy installed, the Claude binary and home come from `t3-policy.json`;
launch arguments (including `--settings`) are ignored; and only these instance variables are
kept: the credential and model variables above, `AWS_REGION`, `AWS_PROFILE` and the four
`DISABLE_*`/`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` switches. Proxy variables,
`NODE_OPTIONS` and `CLAUDE_CONFIG_DIR` are always dropped.
