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
  
  { name: "credit_card", pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g },
  { name: "credit_card_with_separator", pattern: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g },
  { name: "bank_account", pattern: /\b\d{8,17}\b/g },
  { name: "routing_number", pattern: /\b\d{9}\b/g },
  
  { name: "ssn", pattern: /\b\d{3}-\d{2}-\d{4}\b/g },
  { name: "ssn_no_dash", pattern: /\b\d{9}\b/g },
  { name: "email", pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g },
  { name: "phone", pattern: /\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b/g },
  { name: "passport", pattern: /\b[A-Z]{1,2}[0-9]{6,9}\b/g },
  { name: "drivers_license", pattern: /\b[A-Z]{1,2}[0-9]{5,8}\b/g },
  
  { name: "date_of_birth", pattern: /\b(?:0[1-9]|1[0-2])[\/\-](?:0[1-9]|[12][0-9]|3[01])[\/\-](?:19|20)\d{2}\b/g },
  { name: "medical_record", pattern: /\bMRN[:\s]*\d+/gi },
  { name: "insurance", pattern: /\b(?:INS|Policy)[:\s]*[A-Z0-9]{6,}/gi },
];

const EXFILTRATION_TOOLS = [
  "exec",
  "bash",
  "shell", 
  "ssh",
  "scp",
  "curl",
  "wget",
  "nc",
  "netcat",
];

const MAX_SESSION_MESSAGES_TO_SCAN = 10;

function detectSensitiveData(content) {
  if (!content || typeof content !== "string") return [];
  
  const findings = [];
  
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

function checkForExfiltrationTool(toolName) {
  if (!toolName) return null;
  const lower = toolName.toLowerCase();
  return EXFILTRATION_TOOLS.find(cmd => lower.includes(cmd)) || null;
}

function getMessageContent(message) {
  if (!message) return "";
  if (typeof message === "string") return message;
  if (typeof message.content === "string") return message.content;
  if (Array.isArray(message.content)) {
    return message.content.map(c => c.text || "").join(" ");
  }
  return JSON.stringify(message);
}

function getMessageRole(message) {
  if (!message) return "unknown";
  if (message.role) return message.role;
  return "unknown";
}

async function getRecentSessionMessages(sessionKey, agentId = "main") {
  if (!sessionKey || sessionKey === "unknown") return [];
  
  try {
    const stateDir = process.env.OPENCLAW_STATE_DIR || path.join(os.homedir(), ".openclaw");
    const sessionsDir = path.join(stateDir, "agents", agentId, "sessions");
    
    const sessionFile = path.join(sessionsDir, `${sessionKey}.jsonl`);
    
    const content = await fs.readFile(sessionFile, "utf-8");
    const lines = content.trim().split("\n");
    
    const recentLines = lines.slice(-MAX_SESSION_MESSAGES_TO_SCAN);
    const messages = [];
    
    for (const line of recentLines) {
      try {
        const entry = JSON.parse(line);
        if (entry.message && entry.message.role) {
          messages.push(entry.message);
        }
      } catch {
        // Skip invalid JSON lines
      }
    }
    
    return messages;
  } catch (err) {
    console.log("[dlp-monitor] Could not read session messages:", err.message);
    return [];
  }
}

function logAlert(alert) {
  const stateDir = process.env.OPENCLAW_STATE_DIR || path.join(os.homedir(), ".openclaw");
  const logDir = path.join(stateDir, "logs");
  
  fs.mkdir(logDir, { recursive: true }).then(async () => {
    const logFile = path.join(logDir, "dlp-alerts.log");
    const timestamp = new Date().toISOString();
    
    const logLine = JSON.stringify({ ...alert, timestamp }) + "\n";
    await fs.appendFile(logFile, logLine, "utf-8");
    console.log(`[dlp-monitor] ALERT LOGGED: ${alert.event}`);
  }).catch(err => {
    console.error("[dlp-monitor] File write error:", err);
  });
}

const dlpHandler = async (toolResult) => {
  console.log("[dlp-monitor] Tool result hook triggered!", JSON.stringify({
    tool: toolResult.tool,
    hasContent: !!toolResult.result?.content
  }));
  
  const sessionKey = toolResult.sessionKey || "unknown";
  const alerts = [];
  
  try {
    const toolName = toolResult.tool;
    const content = toolResult.result?.content;
    
    if (content) {
      const contentStr = typeof content === 'string' ? content : JSON.stringify(content);
      
      const exfilTool = checkForExfiltrationTool(toolName);
      const sensitiveFindings = detectSensitiveData(contentStr);
      
      if (exfilTool || sensitiveFindings.length > 0) {
        console.log("[dlp-monitor] Detection in tool result!", { exfilTool, sensitiveFindings });
        
        alerts.push({
          event: exfilTool ? "potential_exfiltration_command" : "sensitive_data_in_tool_output",
          tool: toolName,
          exfiltrationTool: exfilTool,
          sensitivePatterns: sensitiveFindings,
          sessionKey
        });
      }
    }
    
    const recentMessages = await getRecentSessionMessages(sessionKey);
    
    for (const message of recentMessages) {
      const msgContent = getMessageContent(message);
      const msgRole = getMessageRole(message);
      
      if (msgRole === "user" || msgRole === "assistant") {
        const findings = detectSensitiveData(msgContent);
        
        if (findings.length > 0) {
          console.log(`[dlp-monitor] Sensitive data in session ${msgRole} message!`, findings);
          
          alerts.push({
            event: "sensitive_data_in_message",
            messageRole: msgRole,
            sensitivePatterns: findings,
            sessionKey
          });
        }
      }
    }
    
    for (const alert of alerts) {
      logAlert(alert);
    }
    
  } catch (err) {
    console.error("[dlp-monitor] Handler error:", err);
  }
  
  return toolResult;
};

export default dlpHandler;
