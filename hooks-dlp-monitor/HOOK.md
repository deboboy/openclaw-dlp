---
name: dlp-monitor
description: "Monitor command outputs for sensitive data patterns and potential data exfiltration"
metadata:
  {
    "openclaw":
      {
        "emoji": "🔐",
        "events": ["command"],
        "requires": {},
      },
  }
---

# DLP Monitor Hook

Monitors command outputs for sensitive data patterns that could indicate data loss.

## What It Does

1. **Monitors all command events** - Triggers on every command issued to the agent
2. **Scans tool outputs** for sensitive data patterns:
   - API keys and tokens
   - AWS credentials
   - Private keys
   - Passwords and secrets
   - JWT tokens
3. **Logs alerts** to `~/.openclaw/logs/dlp-alerts.log`

## Sensitive Data Patterns Detected

- AWS Access Keys: `AKIA[0-9A-Z]{16}`
- Private Keys: `-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----`
- Generic Secrets: `password=|secret=|api_key=|apikey=`
- JWT Tokens: `eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`
- Bearer Tokens: `Bearer [a-zA-Z0-9_-]+`
- GitHub Tokens: `gh[pousr]_[A-Za-z0-9_]{36,}`
- Slack Tokens: `xox[baprs]-[0-9]{10,}`
- Base64 encoded secrets (potential)

## Log Format

```json
{"timestamp":"2026-01-16T14:30:00.000Z","event":"sensitive_data_detected","pattern":"aws_key","sessionKey":"agent:main:main"}
```

## Configuration

No configuration needed by default. The hook runs silently and only logs alerts.

To configure via config:

```json
{
  "hooks": {
    "internal": {
      "entries": {
        "dlp-monitor": { "enabled": true }
      }
    }
  }
}
```

## Usage

Enable the hook:

```bash
openclaw hooks enable dlp-monitor
```

View alerts:

```bash
tail -f ~/.openclaw/logs/dlp-alerts.log
```

Disable:

```bash
openclaw hooks disable dlp-monitor
```
