# OpenClaw DLP Skill

Data Loss Protection skill for OpenClaw - monitors and protects against data leaving the VPS environment.

## Installation

### Skill Only (Knowledge Base)

The skill provides the agent with knowledge about DLP best practices. Install with:

```bash
openclaw skills install https://github.com/deboboy/openclaw-dlp
```

### Full Package (Skill + Hook)

For active monitoring, also enable the DLP hook:

```bash
# The hook monitors commands and logs alerts
openclaw hooks enable dlp-monitor
```

## Components

### SKILL.md
Provides the agent with knowledge about:
- Data exfiltration vectors (curl, wget, nc, scp, etc.)
- Sensitive data patterns (API keys, AWS credentials, private keys)
- Monitoring commands for network activity
- Best practices for handling sensitive data

### hooks-dlp-monitor/
Active hook that monitors command events and logs alerts when:

- Potentially exfiltrating commands are detected (curl, wget, ssh, scp, etc.)
- Sensitive data detected in tool outputs (credit cards, SSN, API keys, etc.)
- Sensitive data detected in session messages (credit cards, SSN, etc. via hourly cron scan)
- Logs to `~/.openclaw/logs/dlp-alerts.log`

### hooks-dlp-monitor/scan-sessions.js
Session scanner that runs hourly via system cron to scan recent session files for sensitive data. Catches sensitive information in messages even when no tools are executed.

## Sensitive Data Patterns Detected

### Credentials & Secrets
- AWS Access Keys: `AKIA[0-9A-Z]{16}`
- Private Keys: `-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----`
- Generic Secrets: `password=`, `secret=`, `api_key=`, `apikey=`
- JWT Tokens
- Bearer Tokens
- GitHub Tokens: `gh[pousr]_...`
- Slack Tokens: `xox[baprs]-...`

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

## View Alerts

```bash
tail -f ~/.openclaw/logs/dlp-alerts.log
```

## License

MIT
