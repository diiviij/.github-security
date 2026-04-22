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
async function callOpenAI(prompt) {
  const { default: fetch } = await import("node-fetch");

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
    throw new Error(`Failed to parse OpenAI response as JSON: ${clean.slice(0, 500)}`);
  }
}

// ─── Format Slack message ──────────────────────────────────────────────────
function buildSlackMessage(result, context) {
  const severityEmoji = {
    NONE: "✅",
    LOW: "🟡",
    MEDIUM: "🟠",
    HIGH: "🔴",
    CRITICAL: "🚨",
  };

  const categoryEmoji = {
    BACKDOOR: "🚪",
    CRYPTO_INJECTION: "🪙",
    DATA_EXFIL: "📤",
    SECRET: "🔑",
    OBFUSCATION: "🎭",
    SUPPLY_CHAIN: "📦",
    STEALTH: "🕵️",
    NETWORK: "🌐",
    OTHER: "⚠️",
  };

  const emoji = severityEmoji[result.severity] || "⚠️";
  const commitUrl = `${context.serverUrl}/${context.repo}/commit/${context.sha}`;
  const actionUrl = `${context.serverUrl}/${context.repo}/actions/runs/${context.runId}`;
  const shortSha = context.sha?.slice(0, 8) || "unknown";

  // Header block
  const headerText =
    result.severity === "NONE" || result.clean
      ? `✅ Security scan passed — no issues found`
      : `${emoji} *Security Alert: ${result.severity} severity issue${result.findings.length > 1 ? "s" : ""} detected*`;

  const blocks = [
    {
      type: "header",
      text: {
        type: "plain_text",
        text:
          result.severity === "NONE" || result.clean
            ? "✅ Security Scan Passed"
            : `${emoji} Security Alert — ${result.severity}`,
        emoji: true,
      },
    },
    {
      type: "section",
      text: {
        type: "mrkdwn",
        text: result.summary,
      },
    },
    { type: "divider" },
    {
      type: "section",
      fields: [
        { type: "mrkdwn", text: `*Repository*\n<${context.serverUrl}/${context.repo}|${context.repo}>` },
        { type: "mrkdwn", text: `*Triggered By*\n${context.actor}` },
        { type: "mrkdwn", text: `*Commit*\n<${commitUrl}|\`${shortSha}\`>` },
        { type: "mrkdwn", text: `*Branch*\n\`${context.ref?.replace("refs/heads/", "") || "unknown"}\`` },
        { type: "mrkdwn", text: `*Event*\n${context.eventName}` },
        { type: "mrkdwn", text: `*Risk Score*\n${result.risk_score}/100` },
      ],
    },
  ];

  // Files changed
  if (context.filesChanged) {
    const files = context.filesChanged
      .split(",")
      .filter(Boolean)
      .slice(0, 10)
      .map((f) => `\`${f.trim()}\``)
      .join(", ");
    blocks.push({
      type: "section",
      text: { type: "mrkdwn", text: `*Files Changed*\n${files}` },
    });
  }

  // Findings
  if (result.findings && result.findings.length > 0) {
    blocks.push({ type: "divider" });
    blocks.push({
      type: "section",
      text: {
        type: "mrkdwn",
        text: `*🔍 ${result.findings.length} Finding${result.findings.length > 1 ? "s" : ""} Detected:*`,
      },
    });

    result.findings.slice(0, 8).forEach((finding, i) => {
      const catEmoji = categoryEmoji[finding.category] || "⚠️";
      const sevEmoji = severityEmoji[finding.severity] || "⚠️";

      blocks.push({
        type: "section",
        text: {
          type: "mrkdwn",
          text: [
            `${sevEmoji} *[${finding.severity}] ${catEmoji} ${finding.title}*`,
            `📁 \`${finding.file}\` ${finding.lines ? `lines ${finding.lines}` : ""}`,
            `📝 ${finding.description}`,
            finding.evidence
              ? `\`\`\`${finding.evidence.slice(0, 200)}\`\`\``
              : "",
            `💡 *Fix:* ${finding.recommendation}`,
          ]
            .filter(Boolean)
            .join("\n"),
        },
      });
    });
  }

  // Action required banner
  if (result.immediate_action_required) {
    blocks.push({ type: "divider" });
    blocks.push({
      type: "section",
      text: {
        type: "mrkdwn",
        text: "🚨 *IMMEDIATE ACTION REQUIRED* — Review and potentially revert this commit before it reaches production.",
      },
    });
  }

  // Notes
  if (result.notes) {
    blocks.push({
      type: "section",
      text: { type: "mrkdwn", text: `📋 *Notes:* ${result.notes}` },
    });
  }

  // Footer
  blocks.push({ type: "divider" });
  blocks.push({
    type: "actions",
    elements: [
      {
        type: "button",
        text: { type: "plain_text", text: "📋 View Commit", emoji: true },
        url: commitUrl,
        style: result.immediate_action_required ? "danger" : "primary",
      },
      {
        type: "button",
        text: { type: "plain_text", text: "⚙️ View Action Run", emoji: true },
        url: actionUrl,
      },
    ],
  });

  blocks.push({
    type: "context",
    elements: [
      {
        type: "mrkdwn",
        text: `🤖 Powered by OpenAI GPT-4o Security Scanner • ${new Date().toUTCString()}`,
      },
    ],
  });

  return {
    text: headerText,
    blocks,
  };
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
