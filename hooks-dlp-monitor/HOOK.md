---
name: dlp-monitor
description: "Monitor tool outputs and session messages for sensitive data patterns and potential data exfiltration"
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

Monitors tool execution outputs AND recent session messages for sensitive data patterns that could indicate data loss.

## What It Does

1. **Monitors all tool executions** - Triggers when a tool result is persisted
2. **Scans recent session messages** - Checks the last 10 messages in the session for sensitive data (user and assistant messages)
3. **Detects sensitive data patterns** in tool outputs and session messages:
   - Credentials & Secrets (API keys, tokens, passwords)
   - Financial Data (credit cards, bank accounts, routing numbers)
   - PII (SSN, email, phone, passport, driver's license)
   - Medical/Healthcare (medical record numbers, insurance info)
4. **Detects exfiltration commands** - curl, wget, ssh, scp, etc.
5. **Logs alerts** to `~/.openclaw/logs/dlp-alerts.log`
6. **Hourly cron scan** - Scans recent session files for sensitive data (runs via system cron)

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
{"timestamp":"2026-01-16T14:30:00.000Z","event":"sensitive_data_in_tool_output","tool":"exec","sensitivePatterns":[{"pattern":"credit_card","count":1}],"sessionKey":"agent:main:main"}
```

```json
{"timestamp":"2026-01-16T14:30:00.000Z","event":"sensitive_data_in_message","messageRole":"user","sensitivePatterns":[{"pattern":"credit_card","count":1}],"sessionKey":"agent:main:main"}
```

```json
{"timestamp":"2026-01-16T14:30:00.000Z","event":"sensitive_data_in_session_scan","messageRole":"user","sensitivePatterns":[{"pattern":"credit_card_with_separator","count":1}],"sessionKey":"agent:main:main","source":"cron-session-scan"}
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

Set up the hourly session scanner (recommended for catching sensitive data in messages):

```bash
# Add system cron job to run hourly
echo "0 * * * * root cd /root/.openclaw/hooks/dlp-monitor && node scan-sessions.js >> /var/log/dlp-scan.log 2>&1" | sudo tee /etc/cron.d/dlp-monitor
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
