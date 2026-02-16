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
- Potentially exfiltrating commands are detected
- Logs to `~/.openclaw/logs/dlp-alerts.log`

## View Alerts

```bash
tail -f ~/.openclaw/logs/dlp-alerts.log
```

## License

MIT
