---
name: data-loss-protection
description: "Monitor and protect against data leaving the VPS environment. Identifies potential data exfiltration via commands, network connections, and file transfers."
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

This skill helps identify and monitor data leaving the VPS environment through various channels.

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

### Data that should be protected:

- API keys and tokens
- Passwords and credentials
- Private keys (SSH, GPG)
- Environment variables containing secrets
- Database connection strings
- Configuration files with sensitive data
- User credentials and personal information
- SSL/TLS certificates

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

- API keys: `[a-zA-Z0-9_-]{32,}`
- AWS keys: `AKIA[0-9A-Z]{16}`
- Private keys: `-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----`
- Generic secrets: `password=|secret=|api_key=|apikey=`
- JWT tokens: `eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*`
- Bearer tokens: `Bearer [a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+`

## Best Practices

1. **Never execute commands that send sensitive data externally** without user confirmation
2. **Audit all curl/wget commands** that send data to external URLs
3. **Check for encoded data** (base64) being transmitted
4. **Monitor large data transfers** - unusual volume may indicate exfiltration
5. **Review any reverse shell patterns** - unexpected outbound connections
6. **Flag commands accessing** `/etc/shadow`, `~/.ssh/`, credential files

## Response Actions

When potential data exfiltration is detected:

1. Note the command and its purpose
2. Warn the user if the command may exfiltrate sensitive data
3. Suggest safer alternatives if applicable
4. Log the event for audit purposes
