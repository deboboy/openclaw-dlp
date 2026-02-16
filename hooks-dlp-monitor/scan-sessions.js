#!/usr/bin/env node

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

const SCAN_HOURS = 24;
const ALERTED_SESSIONS_FILE = "dlp-scanned-sessions.json";

function detectSensitiveData(content) {
  if (!content || typeof content !== "string") return [];
  
  const findings = [];
  
  for (const { name, pattern } of SENSITIVE_PATTERNS) {
    const re = new RegExp(pattern.source, pattern.flags);
    const matches = content.match(re);
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

function getMessageContent(message) {
  if (!message) return "";
  if (typeof message === "string") return message;
  if (typeof message.content === "string") return message.content;
  if (Array.isArray(message.content)) {
    return message.content.map(c => c.text || "").join(" ");
  }
  return JSON.stringify(message);
}

async function loadAlertedSessions() {
  try {
    const stateDir = process.env.OPENCLAW_STATE_DIR || path.join(os.homedir(), ".openclaw");
    const file = path.join(stateDir, "logs", ALERTED_SESSIONS_FILE);
    const data = await fs.readFile(file, "utf-8");
    return new Set(JSON.parse(data));
  } catch {
    return new Set();
  }
}

async function saveAlertedSessions(sessions) {
  const stateDir = process.env.OPENCLAW_STATE_DIR || path.join(os.homedir(), ".openclaw");
  const logDir = path.join(stateDir, "logs");
  await fs.mkdir(logDir, { recursive: true });
  const file = path.join(logDir, ALERTED_SESSIONS_FILE);
  await fs.writeFile(file, JSON.stringify([...sessions]), "utf-8");
}

function logAlert(alert) {
  const stateDir = process.env.OPENCLAW_STATE_DIR || path.join(os.homedir(), ".openclaw");
  const logDir = path.join(stateDir, "logs");
  
  fs.mkdir(logDir, { recursive: true }).then(async () => {
    const logFile = path.join(logDir, "dlp-alerts.log");
    const timestamp = new Date().toISOString();
    const logLine = JSON.stringify({ ...alert, timestamp }) + "\n";
    await fs.appendFile(logFile, logLine, "utf-8");
    console.log(`[dlp-monitor] ALERT: ${alert.event} - ${alert.sensitivePatterns.map(p => p.pattern).join(", ")}`);
  }).catch(err => {
    console.error("[dlp-monitor] File write error:", err);
  });
}

async function scanSessionFile(sessionFile, alertedSessions) {
  try {
    const content = await fs.readFile(sessionFile, "utf-8");
    const lines = content.trim().split("\n");
    const sessionKey = path.basename(sessionFile, ".jsonl");
    
    if (alertedSessions.has(sessionKey)) {
      return;
    }
    
    for (const line of lines) {
      try {
        const entry = JSON.parse(line);
        if (entry.message && entry.message.role) {
          const msgContent = getMessageContent(entry.message);
          const findings = detectSensitiveData(msgContent);
          
          if (findings.length > 0) {
            console.log(`[dlp-monitor] Found sensitive data in ${sessionKey}: ${findings.map(f => f.pattern).join(", ")}`);
            
            logAlert({
              event: "sensitive_data_in_session_scan",
              messageRole: entry.message.role,
              sensitivePatterns: findings,
              sessionKey,
              source: "cron-session-scan"
            });
            
            alertedSessions.add(sessionKey);
          }
        }
      } catch {
        // Skip invalid JSON lines
      }
    }
  } catch (err) {
    console.error(`[dlp-monitor] Error scanning ${sessionFile}:`, err.message);
  }
}

async function main() {
  console.log("[dlp-monitor] Starting session scan...");
  
  const stateDir = process.env.OPENCLAW_STATE_DIR || path.join(os.homedir(), ".openclaw");
  const sessionsDir = path.join(stateDir, "agents", "main", "sessions");
  
  const alertedSessions = await loadAlertedSessions();
  
  const cutoffTime = Date.now() - (SCAN_HOURS * 60 * 60 * 1000);
  
  try {
    const files = await fs.readdir(sessionsDir);
    const jsonlFiles = files.filter(f => f.endsWith(".jsonl"));
    
    for (const file of jsonlFiles) {
      const sessionFile = path.join(sessionsDir, file);
      const stat = await fs.stat(sessionFile);
      
      if (stat.mtimeMs > cutoffTime) {
        await scanSessionFile(sessionFile, alertedSessions);
      }
    }
    
    await saveAlertedSessions(alertedSessions);
    
  } catch (err) {
    console.error("[dlp-monitor] Scan error:", err);
  }
  
  console.log("[dlp-monitor] Session scan complete.");
}

main();
