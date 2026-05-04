const fs = require("fs");
const path = require("path");

const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const SLACK_BOT_TOKEN = process.env.SLACK_BOT_TOKEN;
const SLACK_CHANNEL_ID = process.env.SLACK_CHANNEL_ID || "C07PDMXLA2K";
const SEVERITY_THRESHOLD = process.env.SEVERITY_THRESHOLD || "MEDIUM";

// Minimum confidence (0–100) a finding must have to survive into the alert.
// Findings below this are logged locally but never sent to Slack.
const CONFIDENCE_THRESHOLD = parseInt(process.env.CONFIDENCE_THRESHOLD || "70", 10);

// If ALL surviving findings are LOW severity, don't page — just log.
const ALERT_ON_LOW = process.env.ALERT_ON_LOW === "true";

const SEVERITY_LEVELS = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

// ─── File-path patterns that should lower suspicion ───────────────────────
// These are heuristics applied BEFORE the AI call to annotate the diff,
// giving GPT-4o richer context so it can self-suppress false positives.
const TEST_PATH_PATTERNS = [
  /\/__tests__\//,
  /\.test\.[jt]sx?$/,
  /\.spec\.[jt]sx?$/,
  /\/fixtures\//,
  /\/mocks?\//,
  /\/stubs?\//,
  /\/e2e\//,
  /\/cypress\//,
  /\/jest\//,
];

const DOCS_PATH_PATTERNS = [
  /\.md$/i,
  /\.mdx$/i,
  /\/docs\//,
  /\/examples?\//,
  /\/demo\//,
  /README/i,
  /CHANGELOG/i,
];

const CONFIG_PATH_PATTERNS = [
  /\.json$/,
  /\.ya?ml$/,
  /\.toml$/,
  /\.env\.example$/,
  /\.env\.sample$/,
];

function classifyFile(filePath) {
  if (TEST_PATH_PATTERNS.some((p) => p.test(filePath))) return "TEST";
  if (DOCS_PATH_PATTERNS.some((p) => p.test(filePath))) return "DOCS";
  if (CONFIG_PATH_PATTERNS.some((p) => p.test(filePath))) return "CONFIG";
  return "SOURCE";
}

// ─── Read diff from file ───────────────────────────────────────────────────
function getDiff() {
  const diffPath = "/tmp/scanner/diff.txt";
  if (!fs.existsSync(diffPath)) return "";
  return fs.readFileSync(diffPath, "utf8").trim();
}

// ─── Annotate diff headers with file classification ────────────────────────
// Injects a comment like "# [FILE_TYPE: TEST]" after each "diff --git" line
// so the model knows the file context when it evaluates that hunk.
function annotateDiff(diff) {
  return diff
    .split("\n")
    .map((line) => {
      if (line.startsWith("diff --git ")) {
        // Extract the b/ path from "diff --git a/foo/bar.js b/foo/bar.js"
        const match = line.match(/diff --git a\/.+ b\/(.+)$/);
        if (match) {
          const fileType = classifyFile(match[1]);
          return line + `\n# [FILE_TYPE: ${fileType}]`;
        }
      }
      return line;
    })
    .join("\n");
}

// ─── Compress diff to reduce token usage ──────────────────────────────────
function compressDiff(diff, maxChars = 12000) {
  const lines = diff.split("\n");

  const filtered = lines.filter((line) => {
    return (
      line.startsWith("diff --git") ||
      line.startsWith("# [FILE_TYPE:") ||
      line.startsWith("+++") ||
      line.startsWith("---") ||
      line.startsWith("@@") ||
      line.startsWith("+") ||
      line.startsWith("-")
    );
  });

  let compressed = filtered.join("\n");

  if (compressed.length > maxChars) {
    compressed =
      compressed.slice(0, maxChars) +
      `\n\n... [diff truncated at ${maxChars} chars to fit token limit] ...`;
  }

  return compressed;
}

// ─── Detect project type from changed file extensions ─────────────────────
// Adds project context to the prompt so GPT-4o knows what's "normal" here.
function detectProjectType(filesChanged) {
  const files = filesChanged.split(",").filter(Boolean);
  const counts = { js: 0, ts: 0, py: 0, go: 0, java: 0, rb: 0, sol: 0, other: 0 };

  files.forEach((f) => {
    const ext = f.trim().split(".").pop()?.toLowerCase();
    if (["js", "jsx", "mjs", "cjs"].includes(ext)) counts.js++;
    else if (["ts", "tsx"].includes(ext)) counts.ts++;
    else if (ext === "py") counts.py++;
    else if (ext === "go") counts.go++;
    else if (ext === "java") counts.java++;
    else if (ext === "rb") counts.rb++;
    else if (ext === "sol") counts.sol++;
    else counts.other++;
  });

  const dominant = Object.entries(counts)
    .filter(([k]) => k !== "other")
    .sort((a, b) => b[1] - a[1]);

  if (dominant[0]?.[1] > 0) return dominant[0][0].toUpperCase();
  return "UNKNOWN";
}

// ─── Build the security analysis prompt ───────────────────────────────────
function buildPrompt(diff, context) {
  const projectType = detectProjectType(context.filesChanged);
  const isPR = context.eventName === "pull_request";
  const hasPRTitle = context.prTitle && context.prTitle !== "";

  return `You are a senior security engineer performing a precise, high-signal code security audit.
Your PRIMARY goal is to find REAL threats. Your SECONDARY goal is to avoid false positives — a noisy scanner is ignored.

════════════════════════════════════════════
SCAN CONTEXT
════════════════════════════════════════════
- Repository:     ${context.repo}
- Project type:   ${projectType}
- Actor:          ${context.actor}
- Branch/Ref:     ${context.ref}
- Event:          ${context.eventName}${isPR ? `\n- PR #${context.prNumber}: "${context.prTitle}"` : ""}
- Files changed:  ${context.filesChanged || "N/A"}
- Commits:
${context.commits}

════════════════════════════════════════════
DIFF (file type annotations are in # [FILE_TYPE: ...] comments)
════════════════════════════════════════════
\`\`\`diff
${diff || "No diff content available"}
\`\`\`

════════════════════════════════════════════
WHAT TO FLAG — GENUINE THREATS ONLY
════════════════════════════════════════════

1. 🪙 CRYPTO / BLOCKCHAIN INJECTION
   - Solana, Ethereum, Bitcoin wallet addresses or keypairs added unexpectedly
   - Crypto mining loops (references to mining pools, nonces, hash loops)
   - Web3 libraries added with no obvious business reason
   ⚠ Do NOT flag: blockchain projects adding web3 libs intentionally, address constants in tests

2. 🚪 BACKDOORS & REMOTE ACCESS
   - Reverse shells (bash -i, /dev/tcp, nc -e, socat)
   - Hardcoded credentials or hidden admin accounts
   - New SSH authorized_keys entries
   - Unexpected cron jobs or startup scripts
   - eval/exec of remotely fetched content
   ⚠ Do NOT flag: example/demo commands in documentation, test fixtures with fake creds

3. 📤 DATA EXFILTRATION
   - Code that reads env vars / secrets and sends them to external endpoints
   - File reads immediately followed by HTTP calls to unknown hosts
   - Keyloggers, clipboard hijacking
   ⚠ Do NOT flag: analytics calls with anonymous IDs, error-reporting SDKs (Sentry, Datadog, etc.)

4. 🔑 HARDCODED SECRETS
   - Real API keys, tokens, passwords in source (not .env.example)
   - Private keys (RSA, EC, SSH) in non-test code
   - Real AWS/GCP/Azure credentials
   ⚠ Do NOT flag: placeholder values like "YOUR_API_KEY_HERE", "sk-xxxx", test dummy creds,
     .env.example files, documentation snippets

5. 🎭 OBFUSCATION & ENCODING
   - Large base64 blobs decoded and immediately executed
   - Hex-encoded shellcode
   - eval() of dynamically-constructed strings from external input
   ⚠ Do NOT flag: base64-encoded images/icons, JWT handling, standard crypto usage,
     i18n translation strings, SVG data URIs

6. 📦 SUPPLY CHAIN ATTACKS
   - New npm/pip packages from unknown registries
   - Typosquatted package names (e.g., "lodahs" vs "lodash")
   - postinstall scripts that run shell commands
   - Downgrades to known-vulnerable versions
   ⚠ Do NOT flag: routine dependency upgrades to higher versions, adding well-known packages
     (react, lodash, axios, express, etc.), dev-only devDependencies for testing/linting

7. 🕵️ STEALTH & PERSISTENCE
   - Code that deletes logs or shell history
   - .gitignore changes hiding new suspicious files
   - CI/CD changes that disable or bypass security checks
   ⚠ Do NOT flag: removing debug logs, cleaning up temp files, adding standard ignores like
     node_modules or .DS_Store, legitimate CI optimizations

8. 🌐 SUSPICIOUS NETWORK ACTIVITY
   - HTTP calls to raw IP addresses (not hostnames)
   - Calls to unusual TLDs (.ru, .cn, .tk, .xyz) unrelated to the product
   - DNS tunneling patterns
   ⚠ Do NOT flag: calls to well-known APIs (api.openai.com, api.stripe.com, sentry.io, etc.),
     localhost / 127.0.0.1 in test configs, internal company hostnames

════════════════════════════════════════════
CONFIDENCE SCORING — MANDATORY
════════════════════════════════════════════
Every finding MUST include a "confidence" score from 0–100:
  90–100 → You are certain this is malicious/dangerous code
  70–89  → Strong indicators, context strongly suggests a real threat
  50–69  → Suspicious but could have a legitimate explanation
  0–49   → Possible false positive — do NOT include this as a finding

Only include findings with confidence ≥ 50. If you would rate something below 50, omit it entirely.

KEY SIGNAL BOOSTERS (raise your confidence):
+ The file is FILE_TYPE: SOURCE (not TEST, DOCS, CONFIG)
+ The suspicious code is in a code path that actually executes (not commented out)
+ The destination endpoint is unknown/untrusted
+ The actor is unusual or the change is inconsistent with the PR description
+ The obfuscation has no business justification

KEY SIGNAL REDUCERS (lower your confidence):
- The file is annotated FILE_TYPE: TEST or FILE_TYPE: DOCS
- The suspicious pattern is a well-known, widely-used library
- The PR title / commit message explains the change
- The "secret" looks like a placeholder or example value
- The change is a simple version bump or routine refactor
- The pattern exists in a comment or string literal with no execution path

════════════════════════════════════════════
RESPOND IN THIS EXACT JSON FORMAT — no markdown, no preamble
════════════════════════════════════════════
{
  "clean": true/false,
  "summary": "One-sentence overall assessment",
  "severity": "NONE|LOW|MEDIUM|HIGH|CRITICAL",
  "findings": [
    {
      "id": "FINDING-001",
      "severity": "HIGH",
      "confidence": 85,
      "category": "BACKDOOR|CRYPTO_INJECTION|DATA_EXFIL|SECRET|OBFUSCATION|SUPPLY_CHAIN|STEALTH|NETWORK|OTHER",
      "title": "Short title of the issue",
      "file": "path/to/file.js",
      "file_type": "SOURCE|TEST|DOCS|CONFIG",
      "lines": "42-55",
      "description": "What this code does and why it is dangerous",
      "evidence": "The specific suspicious code snippet (max 200 chars)",
      "false_positive_check": "Explain why you ruled out this being a false positive",
      "recommendation": "What to do about it"
    }
  ],
  "suppressed_count": 0,
  "risk_score": 0,
  "immediate_action_required": true/false,
  "notes": "Any additional context or observations"
}

The "suppressed_count" field should contain the number of potential findings you considered but suppressed due to low confidence or false-positive signals. This helps calibrate the scanner over time.`;
}

// ─── Two-pass verification for findings above HIGH ────────────────────────
// For CRITICAL/HIGH findings, asks GPT-4o to adversarially challenge its own finding.
// This significantly reduces high-severity false positives which are the most disruptive.
async function verifyHighSeverityFinding(finding, diff, context) {
  const verifyPrompt = `You are a skeptical security reviewer. A junior analyst flagged the following as a HIGH or CRITICAL security issue. Your job is to challenge it and determine if it is genuine.

ORIGINAL FINDING:
- Title: ${finding.title}
- Category: ${finding.category}
- File: ${finding.file} (${finding.file_type})
- Lines: ${finding.lines}
- Description: ${finding.description}
- Evidence: ${finding.evidence}
- Analyst's false-positive check: ${finding.false_positive_check}

REPOSITORY CONTEXT:
- Repo: ${context.repo}
- PR/Commit: ${context.prTitle || context.commits?.split("\n")[0] || "N/A"}

RELEVANT DIFF SNIPPET:
\`\`\`diff
${diff.split("\n").slice(0, 100).join("\n")}
\`\`\`

Ask yourself:
1. Could this be a legitimate, expected pattern for this type of project?
2. Is the "evidence" actually executed, or is it in a comment/string/test?
3. Does the PR title or commit message explain this change innocuously?
4. Is this a well-known library or SDK being added for a clear purpose?

Respond ONLY in this JSON format:
{
  "confirmed": true/false,
  "adjusted_confidence": 0-100,
  "adjusted_severity": "LOW|MEDIUM|HIGH|CRITICAL",
  "rationale": "Why you confirmed or downgraded this finding"
}`;

  const response = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${OPENAI_API_KEY}`,
    },
    body: JSON.stringify({
      model: "gpt-4o",
      temperature: 0,
      max_tokens: 500,
      response_format: { type: "json_object" },
      messages: [
        {
          role: "system",
          content: "You are a skeptical security reviewer who challenges potential false positives. Respond only in JSON.",
        },
        { role: "user", content: verifyPrompt },
      ],
    }),
  });

  if (!response.ok) return null; // Verification failed, keep original finding

  const data = await response.json();
  const text = data.choices?.[0]?.message?.content || "";
  try {
    return JSON.parse(text.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim());
  } catch {
    return null;
  }
}

// ─── Post-process findings: apply confidence gate + verify high-severity ──
async function filterFindings(findings, diff, context) {
  const surviving = [];
  const suppressed = [];

  for (const finding of findings) {
    // Gate 1: Drop anything below confidence threshold
    if ((finding.confidence ?? 50) < CONFIDENCE_THRESHOLD) {
      suppressed.push({ ...finding, suppression_reason: `confidence ${finding.confidence} < threshold ${CONFIDENCE_THRESHOLD}` });
      console.log(`   ⬇  Suppressed [${finding.id}] — confidence ${finding.confidence} below threshold`);
      continue;
    }

    // Gate 2: Test/Docs files get a harder cutoff for LOW/MEDIUM findings
    if (
      ["TEST", "DOCS"].includes(finding.file_type) &&
      ["LOW", "MEDIUM"].includes(finding.severity)
    ) {
      suppressed.push({ ...finding, suppression_reason: "LOW/MEDIUM finding in TEST/DOCS file" });
      console.log(`   ⬇  Suppressed [${finding.id}] — ${finding.severity} in ${finding.file_type} file`);
      continue;
    }

    // Gate 3: Two-pass adversarial verification for HIGH/CRITICAL findings
    if (["HIGH", "CRITICAL"].includes(finding.severity)) {
      console.log(`   🔍 Verifying ${finding.severity} finding [${finding.id}]: ${finding.title}`);
      const verification = await verifyHighSeverityFinding(finding, diff, context);

      if (verification) {
        if (!verification.confirmed || verification.adjusted_confidence < CONFIDENCE_THRESHOLD) {
          suppressed.push({
            ...finding,
            suppression_reason: `Verification failed: ${verification.rationale}`,
          });
          console.log(`   ⬇  Suppressed after verification: ${verification.rationale}`);
          continue;
        }

        // Update finding with verification-adjusted values
        finding.confidence = verification.adjusted_confidence;
        finding.severity = verification.adjusted_severity;
        finding.verification_note = verification.rationale;
        console.log(`   ✅ Confirmed [${finding.id}] at ${finding.severity} (confidence: ${finding.confidence})`);
      }
    }

    surviving.push(finding);
  }

  return { surviving, suppressed };
}

// ─── Recalculate overall severity from surviving findings only ─────────────
function recalculateSeverity(findings) {
  if (!findings || findings.length === 0) return "NONE";
  const levels = findings.map((f) => SEVERITY_LEVELS[f.severity] || 0);
  const max = Math.max(...levels);
  return Object.entries(SEVERITY_LEVELS).find(([, v]) => v === max)?.[0] || "NONE";
}

// ─── Call OpenAI API ───────────────────────────────────────────────────────
async function callOpenAI(prompt) {
  const response = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${OPENAI_API_KEY}`,
    },
    body: JSON.stringify({
      model: "gpt-4o",
      temperature: 0,
      max_tokens: 8000,
      response_format: { type: "json_object" },
      messages: [
        {
          role: "system",
          content:
            "You are an expert security engineer. You respond only in valid JSON — no markdown, no preamble, no explanation outside the JSON object.",
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
  const clean = text.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();

  try {
    return JSON.parse(clean);
  } catch {
    console.warn("⚠️  OpenAI response was truncated, attempting partial recovery...");

    const severityMatch = clean.match(/"severity"\s*:\s*"(NONE|LOW|MEDIUM|HIGH|CRITICAL)"/);
    const summaryMatch = clean.match(/"summary"\s*:\s*"([^"]+)"/);
    const cleanMatch = clean.match(/"clean"\s*:\s*(true|false)/);

    if (severityMatch) {
      const sev = severityMatch[1];
      return {
        clean: cleanMatch ? cleanMatch[1] === "true" : false,
        severity: sev,
        summary:
          summaryMatch?.[1] ||
          "Scan completed but response was truncated — manual review recommended.",
        findings: [],
        suppressed_count: 0,
        risk_score:
          sev === "CRITICAL" ? 90 : sev === "HIGH" ? 70 : sev === "MEDIUM" ? 40 : 10,
        immediate_action_required: ["CRITICAL", "HIGH"].includes(sev),
        notes: "⚠️ OpenAI response was truncated. Full diff review is recommended.",
      };
    }

    throw new Error(`Failed to parse OpenAI response as JSON: ${clean.slice(0, 500)}`);
  }
}

// ─── Format Slack message ──────────────────────────────────────────────────
function buildSlackMessage(result, context, suppressedCount) {
  const severityEmoji = { NONE: "✅", LOW: "🟡", MEDIUM: "🟠", HIGH: "🔴", CRITICAL: "🚨" };
  const severityColor = {
    NONE: "#2eb886",
    LOW: "#daa520",
    MEDIUM: "#e8a838",
    HIGH: "#e01e5a",
    CRITICAL: "#7b0d1e",
  };
  const categoryLabel = {
    BACKDOOR: "Backdoor",
    CRYPTO_INJECTION: "Crypto Injection",
    DATA_EXFIL: "Data Exfiltration",
    SECRET: "Secret / Credential",
    OBFUSCATION: "Obfuscation",
    SUPPLY_CHAIN: "Supply Chain",
    STEALTH: "Stealth / Persistence",
    NETWORK: "Suspicious Network",
    OTHER: "Other",
  };

  const isClean = result.severity === "NONE" || result.clean;
  const emoji = severityEmoji[result.severity] || "⚠️";
  const color = severityColor[result.severity] || severityColor.MEDIUM;
  const commitUrl = `${context.serverUrl}/${context.repo}/commit/${context.sha}`;
  const actionUrl = `${context.serverUrl}/${context.repo}/actions/runs/${context.runId}`;
  const shortSha = context.sha?.slice(0, 8) || "unknown";
  const branch = context.ref?.replace("refs/heads/", "") || "unknown";

  const blocks = [
    {
      type: "header",
      text: {
        type: "plain_text",
        text: isClean
          ? `${emoji} Security Scan Passed`
          : `${emoji} Security Alert — ${result.severity}`,
        emoji: true,
      },
    },
    {
      type: "section",
      text: { type: "mrkdwn", text: result.summary },
    },
    { type: "divider" },
    {
      type: "section",
      fields: [
        {
          type: "mrkdwn",
          text: `*Repository*\n<${context.serverUrl}/${context.repo}|${context.repo}>`,
        },
        { type: "mrkdwn", text: `*Actor*\n${context.actor}` },
        { type: "mrkdwn", text: `*Commit*\n<${commitUrl}|\`${shortSha}\`>` },
        { type: "mrkdwn", text: `*Branch*\n\`${branch}\`` },
        { type: "mrkdwn", text: `*Event*\n${context.eventName}` },
        { type: "mrkdwn", text: `*Risk Score*\n${result.risk_score} / 100` },
      ],
    },
  ];

  if (context.filesChanged) {
    const files = context.filesChanged
      .split(",")
      .filter(Boolean)
      .slice(0, 10)
      .map((f) => `\`${f.trim()}\``)
      .join("  ·  ");
    blocks.push({
      type: "section",
      text: { type: "mrkdwn", text: `*Files Changed*\n${files}` },
    });
  }

  if (result.findings?.length > 0) {
    blocks.push({ type: "divider" });
    blocks.push({
      type: "section",
      text: {
        type: "mrkdwn",
        text: `*${result.findings.length} Verified Finding${result.findings.length !== 1 ? "s" : ""} Detected*${suppressedCount > 0 ? `  _(${suppressedCount} low-confidence findings suppressed)_` : ""}`,
      },
    });

    result.findings.slice(0, 8).forEach((finding, i) => {
      const sevEmoji = severityEmoji[finding.severity] || "⚠️";
      const label = categoryLabel[finding.category] || "Other";
      const location = finding.lines
        ? `\`${finding.file}\`  ·  lines ${finding.lines}`
        : `\`${finding.file}\``;

      const lines = [
        `${sevEmoji}  *${finding.title}*`,
        `*Severity:* ${finding.severity}   *Confidence:* ${finding.confidence ?? "N/A"}%   *Category:* ${label}`,
        `*Location:* ${location}  _(${finding.file_type || "SOURCE"})_`,
        finding.description,
      ];

      if (finding.evidence) {
        lines.push(`\`\`\`${finding.evidence.slice(0, 200)}\`\`\``);
      }

      lines.push(`*Recommendation:* ${finding.recommendation}`);

      if (finding.verification_note) {
        lines.push(`_✅ Verified: ${finding.verification_note}_`);
      }

      blocks.push({
        type: "section",
        text: { type: "mrkdwn", text: lines.join("\n") },
      });

      if (i < Math.min(result.findings.length, 8) - 1) {
        blocks.push({ type: "divider" });
      }
    });
  }

  if (result.immediate_action_required) {
    blocks.push({ type: "divider" });
    blocks.push({
      type: "section",
      text: {
        type: "mrkdwn",
        text: ":rotating_light: *Immediate Action Required* — Review and consider reverting this commit before it reaches production.",
      },
    });
  }

  blocks.push({ type: "divider" });
  blocks.push({
    type: "actions",
    elements: [
      {
        type: "button",
        text: { type: "plain_text", text: "View Commit", emoji: false },
        url: commitUrl,
        style: result.immediate_action_required ? "danger" : "primary",
      },
      {
        type: "button",
        text: { type: "plain_text", text: "View Action Run", emoji: false },
        url: actionUrl,
      },
    ],
  });

  const footerParts = [
    `Powered by OpenAI GPT-4o  ·  Confidence threshold: ${CONFIDENCE_THRESHOLD}%`,
    new Date().toUTCString(),
  ];
  if (result.notes) footerParts.splice(1, 0, result.notes);

  blocks.push({
    type: "context",
    elements: [{ type: "mrkdwn", text: footerParts.join("  ·  ") }],
  });

  return {
    text: isClean
      ? "Security scan passed — no verified issues found"
      : `${emoji} Security Alert: ${result.severity} severity detected in ${context.repo}`,
    attachments: [{ color, blocks }],
  };
}

// ─── Send Slack notification ───────────────────────────────────────────────
async function sendSlack(payload) {
  const body = { channel: SLACK_CHANNEL_ID, ...payload };

  const response = await fetch("https://slack.com/api/chat.postMessage", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${SLACK_BOT_TOKEN}`,
    },
    body: JSON.stringify(body),
  });

  const data = await response.json();

  if (!response.ok || !data.ok) {
    throw new Error(
      `Slack API error: ${data.error || response.status} — ${JSON.stringify(data)}`
    );
  }

  console.log(`✅ Slack notification sent to channel ${SLACK_CHANNEL_ID} (ts: ${data.ts})`);
}

// ─── Write GitHub Step Summary result ─────────────────────────────────────
function writeResult(result, suppressedCount) {
  const lines = [
    `**Severity:** ${result.severity}`,
    `**Risk Score:** ${result.risk_score}/100`,
    `**Summary:** ${result.summary}`,
    `**Confidence Threshold:** ${CONFIDENCE_THRESHOLD}%`,
    "",
  ];

  if (result.findings?.length > 0) {
    lines.push("**Verified Findings:**");
    result.findings.forEach((f) => {
      lines.push(
        `- [${f.severity}] ${f.title} — \`${f.file}\` (confidence: ${f.confidence ?? "N/A"}%)`
      );
    });
  } else {
    lines.push("✅ No verified security issues found.");
  }

  if (suppressedCount > 0) {
    lines.push("");
    lines.push(`_${suppressedCount} low-confidence finding(s) were suppressed._`);
  }

  fs.writeFileSync("/tmp/scanner/result.txt", lines.join("\n"));
}

// ─── Main ──────────────────────────────────────────────────────────────────
async function main() {
  console.log("🔐 Starting AI Security Scanner (false-positive-resistant mode)...\n");

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

  if (rawDiff.length === 0) {
    console.log("ℹ️  No diff content to scan (empty diff)");
    writeResult({ severity: "NONE", risk_score: 0, summary: "No diff content to scan.", findings: [] }, 0);
    return;
  }

  const annotatedDiff = annotateDiff(rawDiff);
  const diff = compressDiff(annotatedDiff);
  console.log(`📦 Compressed + annotated diff size: ${diff.length} characters`);

  console.log("🤖 Sending to OpenAI GPT-4o for analysis...");
  const prompt = buildPrompt(diff, context);

  let result;
  try {
    result = await callOpenAI(prompt);
  } catch (err) {
    console.error("❌ OpenAI analysis failed:", err.message);
    try {
      await sendSlack({
        text: "Security scan failed — manual review recommended",
        attachments: [
          {
            color: "#e8a838",
            blocks: [
              {
                type: "header",
                text: { type: "plain_text", text: "⚠️ Security Scan Failed", emoji: true },
              },
              {
                type: "section",
                fields: [
                  { type: "mrkdwn", text: `*Repository*\n${context.repo}` },
                  { type: "mrkdwn", text: `*Actor*\n${context.actor}` },
                  { type: "mrkdwn", text: `*Branch*\n${context.ref}` },
                ],
              },
              { type: "divider" },
              {
                type: "section",
                text: {
                  type: "mrkdwn",
                  text: `*Error:*\n\`\`\`${err.message.slice(0, 500)}\`\`\`\n*Manual review of this commit is recommended.*`,
                },
              },
            ],
          },
        ],
      });
    } catch (slackErr) {
      console.error("❌ Also failed to send Slack error alert:", slackErr.message);
    }
    process.exit(1);
  }

  console.log(`\n📊 Raw Scan Result (before filtering):`);
  console.log(`   Severity:  ${result.severity}`);
  console.log(`   Findings:  ${result.findings?.length || 0}`);
  console.log(`   Suppressed by model: ${result.suppressed_count || 0}`);

  // ── Apply confidence gate + adversarial verification ──
  console.log(`\n🔬 Applying confidence gate (threshold: ${CONFIDENCE_THRESHOLD}%) and verifying high-severity findings...`);
  const { surviving, suppressed } = await filterFindings(result.findings || [], diff, context);
  const totalSuppressed = (result.suppressed_count || 0) + suppressed.length;

  // Recalculate overall severity from only verified, surviving findings
  result.findings = surviving;
  result.severity = recalculateSeverity(surviving);
  result.clean = surviving.length === 0;
  result.immediate_action_required =
    surviving.some((f) => f.severity === "CRITICAL") ||
    (result.immediate_action_required && surviving.length > 0);

  console.log(`\n📊 Final Result (after filtering):`);
  console.log(`   Severity:   ${result.severity}`);
  console.log(`   Risk Score: ${result.risk_score}/100`);
  console.log(`   Findings:   ${surviving.length} verified  |  ${totalSuppressed} suppressed`);
  console.log(`   Summary:    ${result.summary}`);

  writeResult(result, totalSuppressed);

  // ── Alert decision ──
  const thresholdLevel = SEVERITY_LEVELS[SEVERITY_THRESHOLD] || 2;
  const resultLevel = SEVERITY_LEVELS[result.severity] || 0;
  const allLow = surviving.length > 0 && surviving.every((f) => f.severity === "LOW");
  const shouldAlert =
    (resultLevel >= thresholdLevel || result.immediate_action_required) &&
    (!allLow || ALERT_ON_LOW);

  if (shouldAlert) {
    console.log("\n📣 Sending Slack alert...");
    const slackPayload = buildSlackMessage(result, context, totalSuppressed);
    await sendSlack(slackPayload);
  } else {
    console.log(
      `\n✅ No alert sent — severity "${result.severity}" is below threshold or all findings suppressed.`
    );
  }

  // Fail the workflow for CRITICAL issues to optionally block merges
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
