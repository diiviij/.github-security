/**
 * 🔐 AI-Powered Git Security Scanner
 * Uses OpenAI GPT-4o to analyze git diffs for security threats
 * Sends detailed Slack alerts on suspicious findings
 */

const fs = require("fs");
const path = require("path");

const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const SLACK_BOT_TOKEN = process.env.SLACK_BOT_TOKEN;
const SLACK_CHANNEL_ID = process.env.SLACK_CHANNEL_ID || "C07PDMXLA2K";
const SEVERITY_THRESHOLD = process.env.SEVERITY_THRESHOLD || "MEDIUM";

const SEVERITY_LEVELS = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

// ─── Read diff from file ───────────────────────────────────────────────────
function getDiff() {
  const diffPath = "/tmp/scanner/diff.txt";
  if (!fs.existsSync(diffPath)) return "";
  const diff = fs.readFileSync(diffPath, "utf8").trim();
  return diff || "";
}

// ─── Build the security analysis prompt ───────────────────────────────────
function buildPrompt(diff, context) {
  return `You are an expert security engineer performing a code security audit on a git diff.
Your job is to identify REAL security threats — not style issues or minor bugs.

CONTEXT:
- Repository: ${context.repo}
- Actor (who pushed): ${context.actor}
- Branch/Ref: ${context.ref}
- Event: ${context.eventName}
- Files changed: ${context.filesChanged}
- Commits:
${context.commits}

GIT DIFF TO ANALYZE:
\`\`\`diff
${diff || "No diff content available"}
\`\`\`

WHAT TO LOOK FOR (be thorough, these are real attack patterns we've seen):

1. 🪙 CRYPTO / BLOCKCHAIN INJECTION
   - Solana, Ethereum, Bitcoin wallet addresses or keypairs
   - Crypto mining code (references to mining pools, nonces, hashes in loops)
   - NFT minting code appearing unexpectedly
   - Web3 libraries added without obvious reason

2. 🚪 BACKDOORS & REMOTE ACCESS
   - Reverse shells (bash -i, /dev/tcp, nc -e, socat)
   - Hidden admin accounts or hardcoded credentials
   - New SSH authorized keys
   - Unexpected cron jobs or startup scripts
   - Process spawning with eval/exec of remote content

3. 📤 DATA EXFILTRATION
   - Code that reads env vars / secrets and sends them externally
   - Unexpected HTTP calls to unknown domains with sensitive data
   - File reads followed by network calls
   - Clipboard hijacking, keyloggers

4. 🔑 SECRETS & CREDENTIALS
   - API keys, tokens, passwords hardcoded in source
   - Private keys (RSA, EC, SSH) in code
   - AWS/GCP/Azure credentials
   - Database connection strings with credentials

5. 🎭 OBFUSCATION & ENCODING
   - Large base64 blobs being decoded and executed
   - Hex-encoded shellcode
   - Eval of dynamically constructed strings
   - Intentionally obfuscated variable names hiding malicious logic

6. 📦 SUPPLY CHAIN ATTACKS
   - New dependencies from unknown registries
   - Typosquatted package names (e.g., "lodahs" instead of "lodash")
   - Packages with install scripts that run shell commands
   - Sudden version downgrades to known-vulnerable versions
   - Changes to package-lock.json or yarn.lock that don't match package.json

7. 🕵️ STEALTH & PERSISTENCE
   - Code that deletes logs or history
   - Attempts to hide processes or files
   - Modifications to .gitignore to hide suspicious files
   - Changes to CI/CD pipelines that weaken security checks
   - Disabling security tools or scanners

8. 🌐 SUSPICIOUS NETWORK ACTIVITY
   - Calls to IP addresses instead of domain names
   - Calls to unusual TLDs (.ru, .cn, .tk, .xyz) for a company codebase
   - DNS tunneling patterns
   - Webhook calls to unknown services

IMPORTANT RULES:
- Only flag GENUINE security concerns, not code style or logic bugs
- Consider the CONTEXT — is this change expected for this type of repo?
- If the diff is empty or trivial (whitespace, comments only), say so
- Rate each finding by severity: LOW / MEDIUM / HIGH / CRITICAL
- Be specific about WHICH file and WHICH lines are suspicious

RESPOND IN THIS EXACT JSON FORMAT (no markdown, no preamble):
{
  "clean": true/false,
  "summary": "One sentence overall assessment",
  "severity": "NONE|LOW|MEDIUM|HIGH|CRITICAL",
  "findings": [
    {
      "id": "FINDING-001",
      "severity": "HIGH",
      "category": "BACKDOOR|CRYPTO_INJECTION|DATA_EXFIL|SECRET|OBFUSCATION|SUPPLY_CHAIN|STEALTH|NETWORK|OTHER",
      "title": "Short title of the issue",
      "file": "path/to/file.js",
      "lines": "42-55",
      "description": "What this code does and why it's dangerous",
      "evidence": "The specific suspicious code snippet (max 200 chars)",
      "recommendation": "What to do about it"
    }
  ],
  "risk_score": 0-100,
  "immediate_action_required": true/false,
  "notes": "Any additional context or observations"
}`;
}

// ─── Call OpenAI API ───────────────────────────────────────────────────────
// ─── Sleep helper ─────────────────────────────────────────────────────────
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ─── Call OpenAI API with retry + exponential backoff on 429 ──────────────
async function callOpenAI(prompt, retries = 4) {
  const { default: fetch } = await import("node-fetch");

  for (let attempt = 1; attempt <= retries; attempt++) {
    console.log(`🤖 OpenAI attempt ${attempt}/${retries}...`);

    const response = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${OPENAI_API_KEY}`,
      },
      body: JSON.stringify({
        model: "gpt-4o",
        temperature: 0,
        max_tokens: 4000,
        response_format: { type: "json_object" },
        messages: [
          {
            role: "system",
            content: "You are an expert security engineer. You respond only in valid JSON — no markdown, no preamble, no explanation outside the JSON object.",
          },
          { role: "user", content: prompt },
        ],
      }),
    });

    // ── Rate limited (429) — wait and retry ─────────────────────────────
    if (response.status === 429) {
      // Respect Retry-After header if OpenAI sends one, else use backoff
      const retryAfter = response.headers.get("retry-after");
      const waitSeconds = retryAfter
        ? parseInt(retryAfter, 10) + 2          // header + 2s buffer
        : Math.min(15 * Math.pow(2, attempt - 1), 120); // 15s, 30s, 60s, 120s

      console.warn(`⚠️  Rate limited (429). Waiting ${waitSeconds}s before retry ${attempt}/${retries}...`);
      await sleep(waitSeconds * 1000);
      continue; // retry
    }

    // ── Server errors (500/502/503) — short wait and retry ───────────────
    if (response.status >= 500) {
      const waitSeconds = 10 * attempt;
      console.warn(`⚠️  Server error ${response.status}. Waiting ${waitSeconds}s...`);
      await sleep(waitSeconds * 1000);
      continue;
    }

    // ── Any other non-OK ─────────────────────────────────────────────────
    if (!response.ok) {
      const err = await response.text();
      throw new Error(`OpenAI API error ${response.status}: ${err}`);
    }

    // ── Success ──────────────────────────────────────────────────────────
    const data = await response.json();
    const text = data.choices?.[0]?.message?.content || "";
    const clean = text.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();

    try {
      return JSON.parse(clean);
    } catch {
      // Truncated response — try partial recovery
      console.warn("⚠️  Response truncated, attempting partial recovery...");
      const severityMatch = clean.match(/"severity"\s*:\s*"(NONE|LOW|MEDIUM|HIGH|CRITICAL)"/);
      const summaryMatch  = clean.match(/"summary"\s*:\s*"([^"]+)"/);
      const cleanMatch    = clean.match(/"clean"\s*:\s*(true|false)/);
      if (severityMatch) {
        const sev = severityMatch[1];
        return {
          clean: cleanMatch?.[1] === "true" ?? false,
          severity: sev,
          summary: summaryMatch?.[1] ?? "Scan response was truncated — manual review recommended.",
          findings: [],
          risk_score: sev === "CRITICAL" ? 90 : sev === "HIGH" ? 70 : sev === "MEDIUM" ? 40 : 10,
          immediate_action_required: ["CRITICAL", "HIGH"].includes(sev),
          notes: "⚠️ OpenAI response was truncated. Findings list may be incomplete.",
        };
      }
      throw new Error(`Failed to parse OpenAI response: ${clean.slice(0, 300)}`);
    }
  }

  throw new Error(`OpenAI API failed after ${retries} attempts (rate limit or server error).`);
}

// ─── Format Slack message ──────────────────────────────────────────────────
function buildSlackMessage(result, context) {
  const isPassed  = result.severity === "NONE" || result.clean;
  const isCrit    = result.severity === "CRITICAL";
  const isHigh    = result.severity === "HIGH";

  const SEVERITY_CONFIG = {
    NONE:     { emoji: "✅", label: "PASSED",   bar: "▓▓▓▓▓▓▓▓▓▓", color: "good" },
    LOW:      { emoji: "🟡", label: "LOW",       bar: "▓▓░░░░░░░░", color: "warning" },
    MEDIUM:   { emoji: "🟠", label: "MEDIUM",    bar: "▓▓▓▓▓░░░░░", color: "warning" },
    HIGH:     { emoji: "🔴", label: "HIGH",      bar: "▓▓▓▓▓▓▓▓░░", color: "danger" },
    CRITICAL: { emoji: "🚨", label: "CRITICAL",  bar: "▓▓▓▓▓▓▓▓▓▓", color: "danger" },
  };

  const CATEGORY_META = {
    BACKDOOR:         { emoji: "🚪", label: "Backdoor / Remote Access" },
    CRYPTO_INJECTION: { emoji: "🪙", label: "Crypto / Blockchain Injection" },
    DATA_EXFIL:       { emoji: "📤", label: "Data Exfiltration" },
    SECRET:           { emoji: "🔑", label: "Hardcoded Secret" },
    OBFUSCATION:      { emoji: "🎭", label: "Obfuscation / Encoding" },
    SUPPLY_CHAIN:     { emoji: "📦", label: "Supply Chain Attack" },
    STEALTH:          { emoji: "🕵️", label: "Stealth / Persistence" },
    NETWORK:          { emoji: "🌐", label: "Suspicious Network Activity" },
    OTHER:            { emoji: "⚠️", label: "Other" },
  };

  const sev       = SEVERITY_CONFIG[result.severity] || SEVERITY_CONFIG.NONE;
  const commitUrl = `${context.serverUrl}/${context.repo}/commit/${context.sha}`;
  const actionUrl = `${context.serverUrl}/${context.repo}/actions/runs/${context.runId}`;
  const repoUrl   = `${context.serverUrl}/${context.repo}`;
  const shortSha  = context.sha?.slice(0, 8) || "unknown";
  const branch    = context.ref?.replace("refs/heads/", "") || "unknown";
  const findCount = result.findings?.length || 0;
  const now       = new Date().toUTCString();

  // ── Risk score bar (10 segments) ────────────────────────────────────────
  const score     = Math.min(100, Math.max(0, result.risk_score || 0));
  const filled    = Math.round(score / 10);
  const riskBar   = "█".repeat(filled) + "░".repeat(10 - filled);
  const riskLabel = score >= 80 ? "🔴" : score >= 50 ? "🟠" : score >= 20 ? "🟡" : "🟢";

  // ── Fallback plain text (for notifications / clients without block support)
  const fallbackText = isPassed
    ? `✅ [${context.repo}] Security scan passed — no issues found`
    : `${sev.emoji} [${context.repo}] ${sev.label} security alert — ${findCount} finding(s) | Risk: ${score}/100`;

  const blocks = [];

  // ════════════════════════════════════════════════════
  // SECTION 1 — STATUS BANNER
  // ════════════════════════════════════════════════════
  blocks.push({
    type: "header",
    text: {
      type: "plain_text",
      emoji: true,
      text: isPassed
        ? "✅  Security Scan Passed — No Issues Found"
        : `${sev.emoji}  Security Alert  ·  ${sev.label}  ·  ${findCount} Finding${findCount !== 1 ? "s" : ""}`,
    },
  });

  // Summary sentence
  blocks.push({
    type: "section",
    text: {
      type: "mrkdwn",
      text: isPassed
        ? `>_${result.summary || "All checks passed. No security issues detected in this commit."}_`
        : `>${result.summary}`,
    },
  });

  blocks.push({ type: "divider" });

  // ════════════════════════════════════════════════════
  // SECTION 2 — COMMIT METADATA (2-column grid)
  // ════════════════════════════════════════════════════
  blocks.push({
    type: "section",
    fields: [
      { type: "mrkdwn", text: `*📦 Repository*\n<${repoUrl}|${context.repo}>` },
      { type: "mrkdwn", text: `*👤 Pushed By*\n\`${context.actor}\`` },
      { type: "mrkdwn", text: `*🔀 Branch*\n\`${branch}\`` },
      { type: "mrkdwn", text: `*#️⃣ Commit*\n<${commitUrl}|\`${shortSha}\`>` },
      { type: "mrkdwn", text: `*⚡ Trigger*\n\`${context.eventName}\`` },
      { type: "mrkdwn", text: `*🕐 Scanned At*\n${now}` },
    ],
  });

  // ════════════════════════════════════════════════════
  // SECTION 3 — RISK SCORE METER
  // ════════════════════════════════════════════════════
  blocks.push({
    type: "section",
    text: {
      type: "mrkdwn",
      text: `*Risk Score*\n${riskLabel} \`${riskBar}\` *${score}/100*`,
    },
  });

  // Files changed (compact, single line)
  if (context.filesChanged) {
    const files = context.filesChanged
      .split(",")
      .map((f) => f.trim())
      .filter(Boolean);
    const shown  = files.slice(0, 6).map((f) => `\`${f}\``).join("  ");
    const extra  = files.length > 6 ? `  _+${files.length - 6} more_` : "";
    blocks.push({
      type: "section",
      text: { type: "mrkdwn", text: `*📁 Files Changed*\n${shown}${extra}` },
    });
  }

  // ════════════════════════════════════════════════════
  // SECTION 4 — FINDINGS (one clean card each)
  // ════════════════════════════════════════════════════
  if (findCount > 0) {
    blocks.push({ type: "divider" });

    blocks.push({
      type: "section",
      text: {
        type: "mrkdwn",
        text: `*🔍 Findings  ·  ${findCount} issue${findCount !== 1 ? "s" : ""} detected*`,
      },
    });

    result.findings.slice(0, 6).forEach((f, i) => {
      const cat    = CATEGORY_META[f.category] || CATEGORY_META.OTHER;
      const sevCfg = SEVERITY_CONFIG[f.severity] || SEVERITY_CONFIG.NONE;

      // Each finding = header line + detail fields
      blocks.push({
        type: "section",
        text: {
          type: "mrkdwn",
          text: [
            `*${i + 1}. ${cat.emoji} ${f.title}*`,
            `${sevCfg.emoji} *${f.severity}*  ·  ${cat.label}  ·  \`${f.file}\`${f.lines ? `  lines ${f.lines}` : ""}`,
          ].join("\n"),
        },
      });

      // Description + evidence + fix as 3 tidy fields
      const detailLines = [];
      if (f.description) detailLines.push(`*What it does*\n${f.description}`);
      if (f.evidence)    detailLines.push(`*Evidence*\n\`\`\`${f.evidence.slice(0, 180)}\`\`\``);
      if (f.recommendation) detailLines.push(`*Recommendation*\n${f.recommendation}`);

      if (detailLines.length > 0) {
        blocks.push({
          type: "section",
          text: { type: "mrkdwn", text: detailLines.join("\n\n") },
        });
      }

      // Thin separator between findings (but not after the last one)
      if (i < Math.min(findCount, 6) - 1) {
        blocks.push({ type: "divider" });
      }
    });

    if (findCount > 6) {
      blocks.push({
        type: "context",
        elements: [{
          type: "mrkdwn",
          text: `_${findCount - 6} more finding(s) not shown — <${actionUrl}|view full report>_`,
        }],
      });
    }
  }

  // ════════════════════════════════════════════════════
  // SECTION 5 — ACTION BANNER (only on urgent findings)
  // ════════════════════════════════════════════════════
  if (result.immediate_action_required) {
    blocks.push({ type: "divider" });
    blocks.push({
      type: "section",
      text: {
        type: "mrkdwn",
        text: [
          `*🚨 Immediate Action Required*`,
          `This commit contains a *${result.severity}* severity issue.`,
          `Review and consider reverting before it reaches production.`,
        ].join("\n"),
      },
    });
  }

  // Notes (only if present and non-trivial)
  if (result.notes && result.notes.length > 10) {
    blocks.push({
      type: "section",
      text: { type: "mrkdwn", text: `📋 *Note:* _${result.notes}_` },
    });
  }

  // ════════════════════════════════════════════════════
  // SECTION 6 — ACTION BUTTONS + FOOTER
  // ════════════════════════════════════════════════════
  blocks.push({ type: "divider" });

  blocks.push({
    type: "actions",
    elements: [
      {
        type: "button",
        text: { type: "plain_text", text: "View Commit", emoji: true },
        url: commitUrl,
        style: (isCrit || isHigh) ? "danger" : "primary",
      },
      {
        type: "button",
        text: { type: "plain_text", text: "View Action Run", emoji: true },
        url: actionUrl,
      },
      {
        type: "button",
        text: { type: "plain_text", text: "View Repository", emoji: true },
        url: repoUrl,
      },
    ],
  });

  blocks.push({
    type: "context",
    elements: [
      { type: "mrkdwn", text: `🤖 *GPT-4o Security Scanner*  ·  ${context.repo}  ·  ${now}` },
    ],
  });

  return { text: fallbackText, blocks };
}

// ─── Send Slack notification ───────────────────────────────────────────────
async function sendSlack(payload) {
  const { default: fetch } = await import("node-fetch");

  // Attach the channel ID to the payload (required for chat.postMessage)
  const body = {
    channel: SLACK_CHANNEL_ID,
    ...payload,
  };

  const response = await fetch("https://slack.com/api/chat.postMessage", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${SLACK_BOT_TOKEN}`,
    },
    body: JSON.stringify(body),
  });

  const data = await response.json();

  if (!response.ok || !data.ok) {
    throw new Error(`Slack API error: ${data.error || response.status} — ${JSON.stringify(data)}`);
  }

  console.log(`✅ Slack notification sent to channel ${SLACK_CHANNEL_ID} (ts: ${data.ts})`);
}

// ─── Write GitHub Step Summary result ─────────────────────────────────────
function writeResult(result) {
  const lines = [
    `**Severity:** ${result.severity}`,
    `**Risk Score:** ${result.risk_score}/100`,
    `**Summary:** ${result.summary}`,
    "",
  ];

  if (result.findings?.length > 0) {
    lines.push("**Findings:**");
    result.findings.forEach((f) => {
      lines.push(`- [${f.severity}] ${f.title} — \`${f.file}\``);
    });
  } else {
    lines.push("✅ No security issues found.");
  }

  fs.writeFileSync("/tmp/scanner/result.txt", lines.join("\n"));
}

// ─── Main ──────────────────────────────────────────────────────────────────
async function main() {
  console.log("🔐 Starting AI Security Scanner...\n");

  if (!OPENAI_API_KEY) {
    console.error("❌ OPENAI_API_KEY not set");
    process.exit(1);
  }

  if (!SLACK_BOT_TOKEN) {
    console.error("❌ SLACK_BOT_TOKEN not set");
    process.exit(1);
  }

  const context = {
    repo: process.env.GITHUB_REPOSITORY || "unknown/repo",
    actor: process.env.GITHUB_ACTOR || "unknown",
    sha: process.env.GITHUB_SHA || "unknown",
    ref: process.env.GITHUB_REF || "unknown",
    eventName: process.env.GITHUB_EVENT_NAME || "unknown",
    serverUrl: process.env.GITHUB_SERVER_URL || "https://github.com",
    runId: process.env.GITHUB_RUN_ID || "0",
    commits: process.env.COMMITS_META || "No commit metadata",
    filesChanged: process.env.FILES_CHANGED || "",
    prNumber: process.env.PR_NUMBER || "",
    prTitle: process.env.PR_TITLE || "",
  };

  const diff = getDiff();
  console.log(`📏 Diff size: ${diff.length} characters`);

  if (diff.length === 0) {
    console.log("ℹ️  No diff content to scan (empty diff)");
    writeResult({
      severity: "NONE",
      risk_score: 0,
      summary: "No diff content to scan.",
      findings: [],
      notes: "",
    });
    return;
  }

  console.log("🤖 Sending to OpenAI GPT-4o for analysis...");
  const prompt = buildPrompt(diff, context);

  let result;
  try {
    result = await callOpenAI(prompt);
  } catch (err) {
    console.error("❌ OpenAI analysis failed:", err.message);
    process.exit(1);
  }

  console.log(`\n📊 Scan Result:`);
  console.log(`   Severity: ${result.severity}`);
  console.log(`   Risk Score: ${result.risk_score}/100`);
  console.log(`   Findings: ${result.findings?.length || 0}`);
  console.log(`   Summary: ${result.summary}`);

  writeResult(result);

  // Determine if we should send a Slack alert
  const thresholdLevel = SEVERITY_LEVELS[SEVERITY_THRESHOLD] || 2;
  const resultLevel = SEVERITY_LEVELS[result.severity] || 0;
  const shouldAlert = resultLevel >= thresholdLevel || result.immediate_action_required;

  if (shouldAlert) {
    console.log("\n📣 Sending Slack alert...");
    const slackPayload = buildSlackMessage(result, context);
    await sendSlack(slackPayload);
  } else {
    console.log(`\n✅ Severity ${result.severity} is below threshold ${SEVERITY_THRESHOLD} — no Slack alert`);
    // Still send a quiet "all clear" for HIGH threshold configs
    if (SEVERITY_THRESHOLD === "HIGH" && result.findings?.length === 0) {
      console.log("   Skipping all-clear notification (no findings)");
    }
  }

  // Exit with error code if critical/high to optionally block merges
  if (result.severity === "CRITICAL" || result.immediate_action_required) {
    console.error("\n🚨 CRITICAL security issue detected! Failing the workflow.");
    process.exit(1);
  }

  console.log("\n✅ Security scan complete.");
}

main().catch((err) => {
  console.error("💥 Scanner crashed:", err);
  process.exit(1);
});
