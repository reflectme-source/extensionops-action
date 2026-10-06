import fs from "node:fs";
import path from "node:path";

const root = process.env.GITHUB_WORKSPACE || process.cwd();
const ignored = new Set([".git", "node_modules", ".next", "dist", "build", "coverage"]);
const findings = [];
const manifestFiles = [];
let manifestSeen = false;
let permissionPenalty = 0;
let scannedFiles = 0;

function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (ignored.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full);
      continue;
    }
    const relative = path.relative(root, full).replaceAll("\\", "/");
    if (!shouldScan(relative)) continue;
    const stat = fs.statSync(full);
    if (stat.size > 512_000) continue;
    const content = fs.readFileSync(full, "utf8");
    scannedFiles += 1;
    scanFile(relative, content);
  }
}

function isChromeManifestPath(file) {
  const normalized = file.replaceAll("\\", "/").toLowerCase();
  if (!(normalized === "manifest.json" || normalized.endsWith("/manifest.json"))) return false;
  const excluded = new Set(["firefox", "mozilla", "safari", "edge", "opera"]);
  return !normalized.split("/").some((segment) => excluded.has(segment));
}

function shouldScan(file) {
  if (file === "manifest.json" || file.endsWith("/manifest.json")) return true;
  if (/^\.github\/workflows\/.*\.ya?ml$/i.test(file)) return true;
  return /(?:publish|release|deploy|review|chrome|webstore|cws)/i.test(file) &&
    /\.(?:js|mjs|cjs|ts|sh|bash|ps1|ya?ml)$/i.test(file);
}

function addFinding(finding) {
  findings.push({ ...finding, evidenceVersion: "1" });
}

function scanFile(file, content) {
  const lines = content.split(/\r?\n/);
  lines.forEach((line, index) => {
    if (line.includes("chromewebstore/v1.1/items")) {
      addFinding({
        ruleId: "CWS_API_V1_ENDPOINT",
        ruleVersion: "1.0.0",
        severity: "blocker",
        file,
        line: index + 1,
        evidence: line.trim().slice(0, 500),
        policySource: "https://developer.chrome.com/docs/webstore/api/v1",
      });
    }
    if (/\beval\s*\(|\bnew\s+Function\s*\(/.test(line)) {
      addFinding({
        ruleId: "REMOTE_CODE_EVAL",
        ruleVersion: "1.0.0",
        severity: "high",
        file,
        line: index + 1,
        evidence: line.trim().slice(0, 500),
        policySource: "https://developer.chrome.com/docs/webstore/program-policies/policies",
      });
    }
  });

  if (/\.ya?ml$/i.test(file)) {
    lines.forEach((line, index) => {
      if (!/uses:\s*PlasmoHQ\/bpp@v3(?:\s|$)/i.test(line)) return;
      const context = lines
        .slice(Math.max(0, index - 3), Math.min(lines.length, index + 15))
        .join("\n");
      const explicitChrome =
        /(?:artifact|chrome-file|chrome-zip|chromeFile|chromeZip)\s*:\s*[^\n#]*chrome/i.test(
          context,
        );
      addFinding({
        ruleId: "CWS_LEGACY_BPP_V3",
        ruleVersion: "1.0.0",
        severity: explicitChrome ? "blocker" : "high",
        file,
        line: index + 1,
        evidence: context.slice(0, 1200),
        policySource: "https://developer.chrome.com/docs/webstore/api/v1",
      });
    });
  }

  if (isChromeManifestPath(file)) {
    manifestFiles.push({ file, content });
  }
}

function scanManifestFile(file, content) {
  let localPermissionPenalty = 0;
  try {
    const manifest = JSON.parse(content);
    if (manifest.manifest_version !== 3) {
      addFinding({
        ruleId: "MANIFEST_VERSION",
        ruleVersion: "1.0.0",
        severity: "blocker",
        file,
        evidence: `manifest_version=${String(manifest.manifest_version)}`,
        policySource: "https://developer.chrome.com/docs/webstore/program-policies/policies",
      });
    }
    const risky = new Set([
      "tabs",
      "history",
      "cookies",
      "webRequest",
      "webRequestBlocking",
      "management",
      "debugger",
    ]);
    for (const permission of manifest.permissions || []) {
      if (risky.has(permission)) localPermissionPenalty += 6;
    }
    if ((manifest.host_permissions || []).includes("<all_urls>")) {
      localPermissionPenalty += 18;
    }
  } catch {
    addFinding({
      ruleId: "MANIFEST_PARSE",
      ruleVersion: "1.0.0",
      severity: "blocker",
      file,
      policySource: "https://developer.chrome.com/docs/webstore/program-policies/policies",
    });
  }
  permissionPenalty = Math.max(permissionPenalty, localPermissionPenalty);
}

function scanActiveManifests() {
  const mv3 = manifestFiles.filter(({ content }) => {
    try {
      return JSON.parse(content).manifest_version === 3;
    } catch {
      return false;
    }
  });
  const active = mv3.length > 0 ? mv3 : manifestFiles;
  manifestSeen = active.length > 0;
  for (const candidate of active) {
    scanManifestFile(candidate.file, candidate.content);
  }
}

walk(root);
scanActiveManifests();

const blockerCount = findings.filter((f) => f.severity === "blocker").length;
const highCount = findings.filter((f) => f.severity === "high").length;
const rawScore = Math.max(0, 100 - blockerCount * 55 - highCount * 22 - Math.min(permissionPenalty, 60));
const score = blockerCount > 0 ? Math.min(rawScore, 49) : rawScore;

const reportDir = path.join(root, ".extensionops");
fs.mkdirSync(reportDir, { recursive: true });
const reportPath = path.join(reportDir, "report.json");
fs.writeFileSync(
  reportPath,
  JSON.stringify(
    {
      schemaVersion: "1",
      generatedAt: new Date().toISOString(),
      commitSha: process.env.GITHUB_SHA || null,
      scannedFiles,
      manifestSeen,
      score,
      findings,
    },
    null,
    2,
  ),
);

const output = process.env.GITHUB_OUTPUT;
if (output) {
  fs.appendFileSync(output, `score=${score}\nreport=.extensionops/report.json\n`);
}

console.log(`ExtensionOps score: ${score}/100; findings: ${findings.length}`);
if (blockerCount > 0) process.exitCode = 2;
