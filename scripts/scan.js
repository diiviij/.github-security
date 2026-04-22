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

// ─── Compress diff to reduce token usage ──────────────────────────────────
function compressDiff(diff, maxChars = 12000) {
  const lines = diff.split("\n");

  // Keep only meaningful lines: file headers, hunks, and changed lines (+/-)
  const filtered = lines.filter((line) => {
    return (
      line.startsWith("diff --git") ||
      line.startsWith("+++") ||
      line.startsWith("---") ||
      line.startsWith("@@") ||
      line.startsWith("+") ||
      line.startsWith("-")
    );
  });

  let compressed = filtered.join("\n");

  // If still too large, truncate with a notice
  if (compressed.length > maxChars) {
    compressed =
      compressed.slice(0, maxChars) +
      `\n\n... [diff truncated at ${maxChars} chars to fit token limit] ...`;
  }

  return compressed;
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
async function callOpenAI(prompt) {
  const response = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${OPENAI_API_KEY}`,
    },
    body: JSON.stringify({
      model: "gpt-4o",
      temperature: 0,
      max_tokens: 8000,
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

  if (!response.ok) {
    const err = await response.text();
    throw new Error(`OpenAI API error ${response.status}: ${err}`);
  }

  const data = await response.json();
  const text = data.choices?.[0]?.message?.content || "";

  // Strip any stray markdown fences just in case
  const clean = text.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();

  try {
    return JSON.parse(clean);
  } catch {
    // Response was likely truncated — try to salvage partial result for Slack alert
    console.warn("⚠️  OpenAI response was truncated, attempting partial recovery...");

    const severityMatch = clean.match(/"severity"\s*:\s*"(NONE|LOW|MEDIUM|HIGH|CRITICAL)"/);
    const summaryMatch  = clean.match(/"summary"\s*:\s*"([^"]+)"/);
    const cleanMatch    = clean.match(/"clean"\s*:\s*(true|false)/);

    if (severityMatch) {
      console.warn("   Recovered partial result from truncated response.");
      const sev = severityMatch[1];
      return {
        clean: cleanMatch ? cleanMatch[1] === "true" : false,
        severity: sev,
        summary: summaryMatch ? summaryMatch[1] : "Scan completed but response was truncated — manual review recommended.",
        findings: [],
        risk_score: sev === "CRITICAL" ? 90 : sev === "HIGH" ? 70 : sev === "MEDIUM" ? 40 : 10,
        immediate_action_required: ["CRITICAL", "HIGH"].includes(sev),
        notes: "⚠️ OpenAI response was truncated. Findings list may be incomplete. Full diff review is recommended.",
      };
    }

    throw new Error(`Failed to parse OpenAI response as JSON: ${clean.slice(0, 500)}`);
  }
}

// ─── Slack helpers ────────────────────────────────────────────────────────
const SEVERITY_META = {
  NONE:     { emoji: "✅", color: "#2EB67D", label: "CLEAN",    bar: "░░░░░░░░░░" },
  LOW:      { emoji: "🟡", color: "#F2C744", label: "LOW",      bar: "██░░░░░░░░" },
  MEDIUM:   { emoji: "🟠", color: "#E8812A", label: "MEDIUM",   bar: "████░░░░░░" },
  HIGH:     { emoji: "🔴", color: "#E01E5A", label: "HIGH",     bar: "███████░░░" },
  CRITICAL: { emoji: "🚨", color: "#6B0F1A", label: "CRITICAL", bar: "██████████" },
};

const CATEGORY_META = {
  BACKDOOR:        { emoji: "🚪", label: "Backdoor / Remote Access" },
  CRYPTO_INJECTION:{ emoji: "🪙", label: "Crypto / Blockchain Injection" },
  DATA_EXFIL:      { emoji: "📤", label: "Data Exfiltration" },
  SECRET:          { emoji: "🔑", label: "Hardcoded Secret / Credential" },
  OBFUSCATION:     { emoji: "🎭", label: "Obfuscation / Encoding" },
  SUPPLY_CHAIN:    { emoji: "📦", label: "Supply Chain Attack" },
  STEALTH:         { emoji: "🕵️",  label: "Stealth / Persistence" },
  NETWORK:         { emoji: "🌐", label: "Suspicious Network Activity" },
  OTHER:           { emoji: "⚠️",  label: "Other" },
};

function riskBar(score) {
  const filled = Math.round(score / 10);
  return "█".repeat(filled) + "░".repeat(10 - filled) + `  ${score}/100`;
}

function plural(n, word) {
  return `${n} ${word}${n !== 1 ? "s" : ""}`;
}

// ─── Build corporate-grade Slack message ──────────────────────────────────
function buildSlackMessage(result, context) {
  const isClean    = result.severity === "NONE" || result.clean;
  const meta       = SEVERITY_META[result.severity] || SEVERITY_META.MEDIUM;
  const commitUrl  = `${context.serverUrl}/${context.repo}/commit/${context.sha}`;
  const actionUrl  = `${context.serverUrl}/${context.repo}/actions/runs/${context.runId}`;
  const repoUrl    = `${context.serverUrl}/${context.repo}`;
  const shortSha   = context.sha?.slice(0, 8) || "unknown";
  const branch     = context.ref?.replace("refs/heads/", "") || "unknown";
  const timestamp  = Math.floor(Date.now() / 1000);
  const findCount  = result.findings?.length || 0;

  // ── Fallback text (notifications / previews) ──
  const fallbackText = isClean
    ? `✅ [${context.repo}] Security scan passed — no issues found`
    : `${meta.emoji} [${context.repo}] ${meta.label} severity alert — ${plural(findCount, "finding")} detected by AI Security Scanner`;

  // ══════════════════════════════════════════════════════════
  // BLOCK 1 — Status Banner
  // ══════════════════════════════════════════════════════════
  const blocks = [
    {
      type: "header",
      text: {
        type: "plain_text",
        text: isClean
          ? "✅  Security Scan — All Clear"
          : `${meta.emoji}  Security Alert  ·  ${meta.label} Severity`,
        emoji: true,
      },
    },
    {
      type: "section",
      text: {
        type: "mrkdwn",
        text: `> ${result.summary}`,
      },
    },
    { type: "divider" },

    // ── BLOCK 2 — Scan Metadata grid ──
    {
      type: "section",
      fields: [
        { type: "mrkdwn", text: `*📁  Repository*\n<${repoUrl}|${context.repo}>` },
        { type: "mrkdwn", text: `*👤  Triggered By*\n\`${context.actor}\`` },
        { type: "mrkdwn", text: `*🔀  Branch*\n\`${branch}\`` },
        { type: "mrkdwn", text: `*🔖  Commit*\n<${commitUrl}|\`${shortSha}\`>` },
        { type: "mrkdwn", text: `*⚡  Event*\n\`${context.eventName}\`` },
        { type: "mrkdwn", text: `*🕐  Scanned At*\n<!date^${timestamp}^{date_short_pretty} {time}|${new Date().toUTCString()}>` },
      ],
    },

    // ── BLOCK 3 — Risk Score ──
    {
      type: "section",
      fields: [
        {
          type: "mrkdwn",
          text: `*🎯  Risk Score*\n\`${riskBar(result.risk_score)}\``,
        },
        {
          type: "mrkdwn",
          text: `*🔍  Findings*\n\`${plural(findCount, "issue")} detected\``,
        },
      ],
    },
  ];

  // ── BLOCK 4 — Files changed ──
  if (context.filesChanged) {
    const fileList = context.filesChanged
      .split(",")
      .map((f) => f.trim())
      .filter(Boolean);
    const shown    = fileList.slice(0, 8).map((f) => `\`${f}\``).join("  ·  ");
    const extra    = fileList.length > 8 ? `  _+${fileList.length - 8} more_` : "";
    blocks.push({
      type: "section",
      text: { type: "mrkdwn", text: `*📂  Files Changed*\n${shown}${extra}` },
    });
  }

  // ══════════════════════════════════════════════════════════
  // FINDINGS SECTION
  // ══════════════════════════════════════════════════════════
  if (findCount > 0) {
    blocks.push({ type: "divider" });
    blocks.push({
      type: "section",
      text: {
        type: "mrkdwn",
        text: `*🔎  ${plural(findCount, "Security Finding")} Detected*`,
      },
    });

    result.findings.slice(0, 6).forEach((f, idx) => {
      const catMeta  = CATEGORY_META[f.category] || CATEGORY_META.OTHER;
      const sevMeta  = SEVERITY_META[f.severity]  || SEVERITY_META.MEDIUM;
      const location = f.lines ? `lines ${f.lines}` : "";

      // Finding header + detail as a single section
      blocks.push({
        type: "section",
        text: {
          type: "mrkdwn",
          text: [
            `*${idx + 1}. ${sevMeta.emoji} [${f.severity}]  ${catMeta.emoji}  ${f.title}*`,
            `*Category:* ${catMeta.label}   |   *File:* \`${f.file}\` ${location}`,
            `*Detail:* ${f.description}`,
            f.evidence ? `\`\`\`${f.evidence.slice(0, 300)}\`\`\`` : null,
            `*Recommendation:* ${f.recommendation}`,
          ].filter(Boolean).join("\n"),
        },
      });

      // Thin divider between findings (skip after last)
      if (idx < Math.min(findCount, 6) - 1) {
        blocks.push({ type: "divider" });
      }
    });

    if (findCount > 6) {
      blocks.push({
        type: "context",
        elements: [
          {
            type: "mrkdwn",
            text: `_${findCount - 6} additional finding${findCount - 6 !== 1 ? "s" : ""} not shown — view the full Action run for complete details._`,
          },
        ],
      });
    }
  }

  // ── BLOCK — Immediate Action Banner ──
  if (result.immediate_action_required) {
    blocks.push({ type: "divider" });
    blocks.push({
      type: "section",
      text: {
        type: "mrkdwn",
        text: "🚨  *IMMEDIATE ACTION REQUIRED*\nThis commit may contain a critical security threat. Review and consider reverting before it reaches a production environment.",
      },
    });
  }

  // ── BLOCK — Notes ──
  if (result.notes) {
    blocks.push({
      type: "context",
      elements: [{ type: "mrkdwn", text: `📋  *Analyst Notes:* ${result.notes}` }],
    });
  }

  // ── BLOCK — Action Buttons ──
  blocks.push({ type: "divider" });
  blocks.push({
    type: "actions",
    elements: [
      {
        type: "button",
        text: { type: "plain_text", text: "🔍 View Commit", emoji: true },
        url: commitUrl,
        style: result.immediate_action_required ? "danger" : "primary",
      },
      {
        type: "button",
        text: { type: "plain_text", text: "⚙️ Action Run Log", emoji: true },
        url: actionUrl,
      },
      {
        type: "button",
        text: { type: "plain_text", text: "📁 Repository", emoji: true },
        url: repoUrl,
      },
    ],
  });

  // ── BLOCK — Footer ──
  blocks.push({
    type: "context",
    elements: [
      {
        type: "mrkdwn",
        text: `🤖  *AI Security Scanner*  ·  Powered by OpenAI GPT-4o  ·  Run <${actionUrl}|#${context.runId}>  ·  <!date^${timestamp}^{date_short_pretty} at {time}|${new Date().toUTCString()}>`,
      },
    ],
  });

  // ══════════════════════════════════════════════════════════
  // ATTACHMENT — provides the left-side color stripe
  // ══════════════════════════════════════════════════════════
  const attachments = [
    {
      color: meta.color,
      fallback: fallbackText,
    },
  ];

  return {
    text: fallbackText,
    blocks,
    attachments,
  };
}

// ─── Build Slack error alert ───────────────────────────────────────────────
function buildErrorMessage(context, errMessage) {
  const repoUrl   = `${context.serverUrl}/${context.repo}`;
  const commitUrl = `${context.serverUrl}/${context.repo}/commit/${context.sha}`;
  const shortSha  = context.sha?.slice(0, 8) || "unknown";
  const timestamp = Math.floor(Date.now() / 1000);

  return {
    text: `⚠️ [${context.repo}] Security scanner encountered an error — manual review required`,
    blocks: [
      {
        type: "header",
        text: { type: "plain_text", text: "⚠️  Security Scanner — Scan Failed", emoji: true },
      },
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: "> The AI security scanner could not complete its analysis. *Manual review of this commit is required.*",
        },
      },
      { type: "divider" },
      {
        type: "section",
        fields: [
          { type: "mrkdwn", text: `*📁  Repository*\n<${repoUrl}|${context.repo}>` },
          { type: "mrkdwn", text: `*👤  Actor*\n\`${context.actor}\`` },
          { type: "mrkdwn", text: `*🔖  Commit*\n<${commitUrl}|\`${shortSha}\`>` },
          { type: "mrkdwn", text: `*🔀  Branch*\n\`${context.ref?.replace("refs/heads/", "") || "unknown"}\`` },
        ],
      },
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: `*❌  Error Details*\n\`\`\`${errMessage.slice(0, 600)}\`\`\``,
        },
      },
      { type: "divider" },
      {
        type: "actions",
        elements: [
          {
            type: "button",
            text: { type: "plain_text", text: "🔍 Review Commit", emoji: true },
            url: commitUrl,
            style: "danger",
          },
          {
            type: "button",
            text: { type: "plain_text", text: "⚙️ View Action Logs", emoji: true },
            url: `${context.serverUrl}/${context.repo}/actions/runs/${context.runId}`,
          },
        ],
      },
      {
        type: "context",
        elements: [
          {
            type: "mrkdwn",
            text: `🤖  *AI Security Scanner*  ·  Scan failed  ·  <!date^${timestamp}^{date_short_pretty} at {time}|${new Date().toUTCString()}>`,
          },
        ],
      },
    ],
    attachments: [{ color: "#E01E5A", fallback: "Security scan failed — manual review required" }],
  };
}

// ─── Send Slack notification ───────────────────────────────────────────────
async function sendSlack(payload) {
  const body = { channel: SLACK_CHANNEL_ID, ...payload };

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

  console.log(`✅ Slack notification sent  (channel: ${SLACK_CHANNEL_ID}  ts: ${data.ts})`);
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

  const rawDiff = getDiff();
  console.log(`📏 Raw diff size: ${rawDiff.length} characters`);
  const diff = compressDiff(rawDiff);
  console.log(`📦 Compressed diff size: ${diff.length} characters`);

  if (rawDiff.length === 0) {
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

    // Still send a Slack alert so the team knows the scan failed
    try {
      await sendSlack(buildErrorMessage(context, err.message));
    } catch (slackErr) {
      console.error("❌ Also failed to send Slack error alert:", slackErr.message);
    }

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
