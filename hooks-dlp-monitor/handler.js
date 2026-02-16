import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

const SENSITIVE_PATTERNS = [
  { name: "aws_key", pattern: /AKIA[0-9A-Z]{16}/g },
  { name: "private_key", pattern: /-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----/g },
  { name: "generic_secret", pattern: /(password|secret|api_key|apikey)\s*[=:]\s*["']?[a-zA-Z0-9_@#$%^&*!]{8,}["']?/gi },
  { name: "jwt_token", pattern: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g },
  { name: "bearer_token", pattern: /Bearer [a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g },
  { name: "github_token", pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/g },
  { name: "slack_token", pattern: /xox[baprs]-[0-9]{10,}/g },
  { name: "base64_secret", pattern: /(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g },
];

const EXFILTRATION_COMMANDS = [
  "curl",
  "wget",
  "nc",
  "netcat",
  "socat",
  "ssh",
  "scp",
  "rsync",
  "ftp",
  "sftp",
  "mail",
  "mailx",
  "sendmail",
  "ncat",
  "telnet",
  "ncftp",
];

function detectSensitiveData(content) {
  if (!content || typeof content !== "string") return [];
  
  const findings = [];
  const lowerContent = content.toLowerCase();
  
  for (const { name, pattern } of SENSITIVE_PATTERNS) {
    const matches = content.match(pattern);
    if (matches && matches.length > 0) {
      findings.push({
        pattern: name,
        count: matches.length,
        preview: matches[0].substring(0, 20) + "..."
      });
    }
  }
  
  return findings;
}

function checkForExfiltrationCommand(commandStr) {
  if (!commandStr) return null;
  
  const lowerCmd = commandStr.toLowerCase();
  for (const cmd of EXFILTRATION_COMMANDS) {
    if (lowerCmd.includes(cmd)) {
      return cmd;
    }
  }
  return null;
}

const dlpHandler = async (event) => {
  if (event.type !== "command") return;
  
  try {
    const stateDir = process.env.OPENCLAW_STATE_DIR || path.join(os.homedir(), ".openclaw");
    const logDir = path.join(stateDir, "logs");
    await fs.mkdir(logDir, { recursive: true });
    const logFile = path.join(logDir, "dlp-alerts.log");
    
    const alerts = [];
    const timestamp = new Date().toISOString();
    
    const cmdStr = event.context?.sessionEntry?.message?.content || "";
    const exfilCmd = checkForExfiltrationCommand(cmdStr);
    
    if (exfilCmd) {
      alerts.push({
        timestamp,
        event: "potential_exfiltration_command",
        command: exfilCmd,
        fullCommand: cmdStr.substring(0, 200),
        sessionKey: event.sessionKey,
        senderId: event.context?.senderId ?? "unknown",
        source: event.context?.commandSource ?? "unknown"
      });
    }
    
    if (alerts.length > 0) {
      for (const alert of alerts) {
        const logLine = JSON.stringify(alert) + "\n";
        await fs.appendFile(logFile, logLine, "utf-8");
        console.log(`[dlp-monitor] ALERT: ${alert.event} - ${alert.command || alert.pattern}`);
      }
    }
  } catch (err) {
    console.error("[dlp-monitor] Error:", err instanceof Error ? err.message : String(err));
  }
};

export default dlpHandler;
