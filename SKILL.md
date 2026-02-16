---
name: data-loss-protection
description: "Monitor and protect against data leaving the VPS environment. Identifies potential data exfiltration via commands, network connections, file transfers, and sensitive data in messages."
metadata:
  {
    "openclaw":
      {
        "emoji": "🔒",
        "requires": {},
      },
  }
---

# Data Loss Protection (DLP)

This skill helps identify and monitor data leaving the VPS environment through various channels, and protects sensitive data from being mishandled.

## Data Exfiltration Vectors

### Network Commands that can send data out:

- **curl/wget**: Fetch or send data to external URLs
- **nc/netcat**: Raw network connections
- **socat**: Proxy and redirect connections
- **ssh**: Secure shell can tunnel data
- **scp/rsync**: File transfer over network
- **ftp/sftp**: File transfer protocols
- **mail/mailx/sendmail**: Email sending
- **ncftp**: FTP client
- **telnet**: Unencrypted connections
- **ncat**: Netcat alternative

### Commands that can read sensitive data:

- **cat/head/tail**: Read file contents
- **grep/ack/ag**: Search file contents
- **find**: Locate files
- **ls -R**: List all files recursively
- **base64**: Encode data for transmission
- **xxd/hexdump**: Convert to binary/hex
- **strings**: Extract readable strings from binaries

## Sensitive Data Categories

### Credentials & Secrets
- API keys and tokens
- Passwords and credentials
- Private keys (SSH, GPG)
- JWT tokens
- OAuth tokens

### Financial Data
- Credit card numbers (Visa, Mastercard, Amex, Discover)
- Bank account numbers
- Routing numbers
- Cryptocurrency wallet addresses

### PII (Personally Identifiable Information)
- Social Security Numbers (SSN)
- Email addresses
- Phone numbers
- Passport numbers
- Driver's license numbers
- Physical addresses
- Dates of birth

### Healthcare Data
- Medical record numbers (MRN)
- Health insurance policy numbers
- Diagnosis codes
- Prescription information

## Monitoring Commands

### List active network connections:

```bash
ss -tunap
netstat -tunap
```

### List recent outbound connections:

```bash
ss -tp | grep ESTAB
```

### Check for suspicious processes:

```bash
ps auxf
ss -pl
```

### Monitor for data transfer:

```bash
iptraf-ng
nethogs
```

### Check cron jobs for scheduled exfiltration:

```bash
crontab -l
ls -la /etc/cron.d/
ls -la /etc/cron.daily/
```

### Check for unusual startup items:

```bash
ls -la /etc/init.d/
systemctl list-unit-files
```

## Pattern Matching for Sensitive Data

When output contains these patterns, flag as sensitive:

### Credentials
- API keys: `[a-zA-Z0-9_-]{32,}`
- AWS keys: `AKIA[0-9A-Z]{16}`
- Private keys: `-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----`
- Generic secrets: `password=|secret=|api_key=|apikey=`
- JWT tokens: `eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`
- Bearer tokens: `Bearer [a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`

### Financial
- Credit cards: `4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}`
- Bank accounts: `\d{8,17: `\d{}`
- Routing numbers9}`

### PII
- SSN: `\d{3}-\d{2}-\d{4}`
- Email: `[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}`
- Phone: `\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}`

## Best Practices

1. **Never execute commands that send sensitive data externally** without user confirmation
2. **Audit all curl/wget commands** that send data to external URLs
3. **Check for encoded data** (base64) being transmitted
4. **Monitor large data transfers** - unusual volume may indicate exfiltration
5. **Review any reverse shell patterns** - unexpected outbound connections
6. **Flag commands accessing** `/etc/shadow`, `~/.ssh/`, credential files
7. **Do NOT repeat or share sensitive data** that appears in conversation
8. **Warn users** when they share sensitive data like credit cards, SSN, etc.

## Response Actions

When potential data exfiltration is detected:

1. Note the command and its purpose
2. Warn the user if the command may exfiltrate sensitive data
3. Suggest safer alternatives if applicable
4. Log the event for audit purposes

When sensitive data is shared by the user:

1. **Do NOT repeat or echo** the sensitive data back
2. **Warn the user** about the sensitivity of the data
3. **Suggest redacting** or masking sensitive information
4. **Do not store** sensitive data in memory or session files unless absolutely necessary
