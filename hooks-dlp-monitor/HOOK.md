---
name: dlp-monitor
description: "Monitor tool outputs for sensitive data patterns and potential data exfiltration"
metadata:
  {
    "openclaw":
      {
        "emoji": "🔐",
        "events": ["tool_result_persist"],
        "requires": {},
      },
  }
---

# DLP Monitor Hook

Monitors tool execution outputs for sensitive data patterns that could indicate data loss.

## What It Does

1. **Monitors all tool executions** - Triggers after each tool runs
2. **Detects sensitive data patterns** in tool outputs:
   - Credentials & Secrets (API keys, tokens, passwords)
   - Financial Data (credit cards, bank accounts, routing numbers)
   - PII (SSN, email, phone, passport, driver's license)
   - Medical/Healthcare (medical record numbers, insurance info)
3. **Detects exfiltration commands** - curl, wget, ssh, scp, etc.
4. **Logs alerts** to `~/.openclaw/logs/dlp-alerts.log`

## Sensitive Data Patterns Detected

### Credentials & Secrets
- AWS Access Keys: `AKIA[0-9A-Z]{16}`
- Private Keys: `-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----`
- Generic Secrets: `password=`, `secret=`, `api_key=`, `apikey=`
- JWT Tokens: `eyJ[a-zA-Z0-9_-]*.eyJ[a-zA-Z0-9_-]*.*`
- Bearer Tokens: `Bearer ...`
- GitHub Tokens: `gh[pousr]_[A-Za-z0-9_]{36,}`
- Slack Tokens: `xox[baprs]-[0-9]{10,}`

### Financial Data
- Credit Cards: Visa, Mastercard, Amex, Discover formats
- Bank Account Numbers: 8-17 digit numbers
- Routing Numbers: 9-digit numbers

### PII (Personally Identifiable Information)
- SSN: `XXX-XX-XXXX` format
- Email Addresses
- Phone Numbers
- Passport Numbers
- Driver's License Numbers
- Dates of Birth

### Healthcare Data
- Medical Record Numbers (MRN)
- Insurance Policy Numbers

## Log Format

```json
{"timestamp":"2026-01-16T14:30:00.000Z","event":"sensitive_data_detected","tool":"exec","sensitivePatterns":[{"pattern":"credit_card","count":1}],"sessionKey":"agent:main:main"}
```

```json
{"timestamp":"2026-01-16T14:30:00.000Z","event":"potential_exfiltration_command","tool":"exec","exfiltrationTool":"curl","sessionKey":"agent:main:main"}
```

## Configuration

No configuration needed by default. The hook runs silently and only logs alerts.

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

## Note

This hook monitors tool outputs for sensitive data patterns. It does NOT block or prevent actions - it simply logs alerts for audit purposes. The agent should use the DLP skill knowledge to make informed decisions about handling sensitive data.
