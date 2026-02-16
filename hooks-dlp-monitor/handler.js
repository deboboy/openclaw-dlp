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

const dlpHandler = (toolResult) => {
  console.log("[dlp-monitor] Tool result hook triggered!", JSON.stringify({
    tool: toolResult.tool,
    hasContent: !!toolResult.result?.content
  }));
  
  try {
    const toolName = toolResult.tool;
    const content = toolResult.result?.content;
    
    if (!content) return toolResult;
    
    const contentStr = typeof content === 'string' ? content : JSON.stringify(content);
    
    const exfilTool = checkForExfiltrationTool(toolName);
    const sensitiveFindings = detectSensitiveData(contentStr);
    
    if (exfilTool || sensitiveFindings.length > 0) {
      console.log("[dlp-monitor] Detection!", { exfilTool, sensitiveFindings });
      
      const stateDir = process.env.OPENCLAW_STATE_DIR || path.join(os.homedir(), ".openclaw");
      const logDir = path.join(stateDir, "logs");
      
      try {
        fs.mkdir(logDir, { recursive: true }).then(async () => {
          const logFile = path.join(logDir, "dlp-alerts.log");
          const timestamp = new Date().toISOString();
          
          const alert = {
            timestamp,
            event: exfilTool ? "potential_exfiltration_command" : "sensitive_data_detected",
            tool: toolName,
            exfiltrationTool: exfilTool,
            sensitivePatterns: sensitiveFindings,
            sessionKey: toolResult.sessionKey || "unknown"
          };
          
          const logLine = JSON.stringify(alert) + "\n";
          await fs.appendFile(logFile, logLine, "utf-8");
          console.log(`[dlp-monitor] ALERT LOGGED: ${alert.event}`);
        }).catch(err => {
          console.error("[dlp-monitor] File write error:", err);
        });
      } catch (err) {
        console.error("[dlp-monitor] Error:", err);
      }
    }
  } catch (err) {
    console.error("[dlp-monitor] Handler error:", err);
  }
  
  return toolResult;
};

export default dlpHandler;
