import fs from "node:fs";
import path from "node:path";

const root = process.env.GITHUB_WORKSPACE || process.cwd();
const ignored = new Set([
  ".git",
  "node_modules",
  ".next",
  "dist",
  "build",
  "coverage",
  "docs",
  "examples",
  "fixtures",
  "__tests__",
  "tests",
]);
const findings = [];
const manifestFiles = [];
const extensionSourceChunks = [];
const packageFiles = [];
const lockDirs = new Set();
const lockfileNames = new Set([
  "package-lock.json",
  "npm-shrinkwrap.json",
  "pnpm-lock.yaml",
  "yarn.lock",
]);
let manifestSeen = false;
let permissionPenalty = 0;
let scannedFiles = 0;

const policySource =
  "https://developer.chrome.com/docs/webstore/program-policies/policies";

function redactEvidence(value, maxLength = 500) {
  let redacted = String(value ?? "").replace(
    /(\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|secret)\b\s*[:=]\s*["'])[^"'\r\n]{8,}(["'])/gi,
    "$1[REDACTED]$2",
  );
  for (const pattern of [
    /sk_(?:live|test)_[A-Za-z0-9_-]{10,}/g,
    /gh[pousr]_[A-Za-z0-9]{20,}/g,
    /github_pat_[A-Za-z0-9_]{20,}/g,
    /xox[baprs]-[A-Za-z0-9-]{10,}/g,
    /AKIA[0-9A-Z]{16}/g,
    /Bearer\s+[A-Za-z0-9._~+/=-]{20,}/gi,
  ]) {
    redacted = redacted.replace(pattern, "[REDACTED]");
  }
  return redacted.slice(0, maxLength);
}

function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (ignored.has(entry.name)) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full);
      continue;
    }
    const relative = path.relative(root, full).replaceAll("\\", "/");
    if (lockfileNames.has(path.posix.basename(relative))) {
      lockDirs.add(path.posix.dirname(relative) === "." ? "" : path.posix.dirname(relative));
    }
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
  if (!(normalized === "manifest.json" || normalized.endsWith("/manifest.json"))) {
    return false;
  }
  const excluded = new Set(["firefox", "mozilla", "safari", "edge", "opera"]);
  return !normalized.split("/").some((segment) => excluded.has(segment));
}

function isExtensionSourceCandidate(file) {
  const normalized = file.replaceAll("\\", "/");
  if (!/\.(?:js|mjs|cjs|ts|tsx|jsx|html)$/i.test(normalized)) return false;
  if (/\.min\.js$/i.test(normalized)) return false;
  if (
    /(?:^|\/)(?:node_modules|vendor|dist|build|coverage|docs?|examples?|fixtures?|__tests__|tests?)(?:\/|$)/i.test(
      normalized,
    )
  ) {
    return false;
  }
  return /(?:background|service[-_.]?worker|content|inject|offscreen|side[-_.]?panel|extension|src\/)/i.test(
    normalized,
  );
}

function shouldScan(file) {
  if (file === "manifest.json" || file.endsWith("/manifest.json")) return true;
  if (/^\.github\/workflows\/.*\.ya?ml$/i.test(file)) return true;
  if (/package\.json$/i.test(file)) return true;
  if (isExtensionSourceCandidate(file)) return true;
  return (
    /(?:publish|release|deploy|review|chrome|webstore|cws)/i.test(file) &&
    /\.(?:js|mjs|cjs|ts|sh|bash|ps1|ya?ml)$/i.test(file)
  );
}

function addFinding(finding) {
  findings.push({ ...finding, evidenceVersion: "2" });
}

function isCwsReferenceOnlySource(file, content) {
  const normalized = file.replaceAll("\\", "/").toLowerCase();

  if (
    /(^|\/)(?:test|tests|__tests__|fixtures?|docs?|examples?|guides?)(\/|$)/.test(
      normalized,
    ) ||
    /\.(?:test|spec)\.[cm]?[jt]sx?$/.test(normalized)
  ) {
    return true;
  }

  // Front-end UI previews and guide pages are examples, not publishing scripts.
  // Keep API routes and release scripts eligible for V1 detection.
  if (/^src\/app\/(?!api\/).*page\.[jt]sx$/i.test(normalized) ||
      /(?:^|\/)landingpreview\.[jt]sx$/i.test(normalized)) {
    return true;
  }

  if (content.includes("const V1_MARKERS") && content.includes("scanCwsV1(")) {
    return true;
  }

  if (
    content.includes("const V1_UPLOAD") &&
    content.includes("const V1_PUBLISH") &&
    content.includes("patchShellCwsV1(")
  ) {
    return true;
  }

  if (
    content.includes("const QUERIES") &&
    content.includes("search/code") &&
    content.includes("scanRepository")
  ) {
    return true;
  }

  return false;
}

function securityFinding({
  ruleId,
  severity,
  file,
  line,
  evidence,
  title,
  impact,
  recommendation,
  confidence = "high",
}) {
  addFinding({
    ruleId,
    ruleVersion: "1.0.0",
    severity,
    confidence,
    file,
    line,
    evidence: evidence === undefined ? undefined : redactEvidence(evidence, 1200),
    title,
    impact,
    recommendation,
    policySource,
  });
}

function scanExtensionSecurity(file, content) {
  if (!/\.(?:js|mjs|cjs|ts|tsx|jsx|html)$/i.test(file)) return;
  if (
    /(?:^|\/)(?:node_modules|vendor|dist|build|coverage|docs?|examples?|fixtures?|__tests__|tests?)(?:\/|$)/i.test(
      file,
    )
  ) {
    return;
  }

  const lines = content.split(/\r?\n/);

  lines.forEach((line, index) => {
    const lineNumber = index + 1;

    if (
      /<script\b[^>]*\bsrc\s*=\s*["']https?:\/\//i.test(line) ||
      /\bimportScripts\s*\(\s*["']https?:\/\//i.test(line) ||
      /\bimport\s*\(\s*["']https?:\/\//i.test(line)
    ) {
      securityFinding({
        ruleId: "REMOTE_HOSTED_CODE",
        severity: "blocker",
        file,
        line: lineNumber,
        evidence: line.trim().slice(0, 300),
        title: "Remote executable code is referenced",
        impact: "High rejection risk and a remote-code supply-chain boundary.",
        recommendation:
          "Bundle executable code into the extension package and keep remote responses data-only.",
      });
    }

    const httpMatch = line.match(
      /(?:fetch\s*\(|axios\.(?:get|post|put|patch|delete)\s*\(|\.open\s*\([^,]+,)\s*["'](http:\/\/[^"']+)/i,
    );
    if (
      httpMatch?.[1] &&
      !/^http:\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?::|\/|$)/i.test(
        httpMatch[1],
      )
    ) {
      securityFinding({
        ruleId: "INSECURE_HTTP_ENDPOINT",
        severity: "medium",
        file,
        line: lineNumber,
        evidence: httpMatch[1].slice(0, 220),
        title: "Unencrypted HTTP endpoint used by extension code",
        impact: "Data integrity/privacy risk and avoidable review friction.",
        recommendation: "Use HTTPS for production network endpoints.",
      });
    }

    const secretMatch = line.match(
      /\b(?:api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|secret)\b\s*[:=]\s*["']([^"'\r\n]{20,})["']/i,
    );
    if (
      secretMatch &&
      /^[A-Za-z0-9_\-./+=]{20,}$/.test(secretMatch[1]) &&
      !/(?:example|placeholder|changeme|your[_-])/i.test(secretMatch[1])
    ) {
      securityFinding({
        ruleId: "HARDCODED_SECRET",
        severity: "high",
        confidence: "heuristic",
        file,
        line: lineNumber,
        evidence: "[credential-like value redacted]",
        title: "Possible hard-coded secret in extension source",
        impact:
          "Secrets shipped in an extension are recoverable and can become account or API abuse vectors.",
        recommendation:
          "Remove the credential from the client bundle and move privileged operations behind an authenticated backend.",
      });
    }
  });

  if (
    /\bonMessageExternal\.addListener\s*\(/.test(content) &&
    !/(?:sender\.(?:id|origin|url)|allowedSender|allowedOrigin|trustedSender)/.test(
      content,
    )
  ) {
    securityFinding({
      ruleId: "EXTERNAL_MESSAGE_VALIDATION",
      severity: "medium",
      confidence: "heuristic",
      file,
      title: "External message handler has no visible sender validation",
      impact:
        "An overly permissive messaging boundary can expose privileged extension actions to untrusted callers.",
      recommendation:
        "Validate sender.id/origin against an explicit allowlist before privileged actions.",
    });
  }
}

function scanFile(file, content) {
  if (isExtensionSourceCandidate(file)) {
    extensionSourceChunks.push(content);
  }
  const lines = content.split(/\r?\n/);
  const cwsReferenceOnly = isCwsReferenceOnlySource(file, content);

  lines.forEach((line, index) => {
    if (!cwsReferenceOnly && line.includes("chromewebstore/v1.1/items")) {
      addFinding({
        ruleId: "CWS_API_V1_ENDPOINT",
        ruleVersion: "1.0.0",
        severity: "blocker",
        file,
        line: index + 1,
        evidence: redactEvidence(line.trim(), 500),
        policySource: "https://developer.chrome.com/docs/webstore/api/v1",
      });
    }
    if (/\beval\s*\(|\bnew\s+Function\s*\(/.test(line)) {
      securityFinding({
        ruleId: "REMOTE_CODE_EVAL",
        severity: "high",
        file,
        line: index + 1,
        evidence: line.trim().slice(0, 500),
        title: "Dynamic code execution detected",
        impact: "Dynamic code execution weakens reviewability and can violate packaged-code expectations.",
        recommendation:
          "Replace runtime code generation with packaged, statically analyzable logic.",
      });
    }
  });

  scanExtensionSecurity(file, content);

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
        evidence: redactEvidence(context, 1200),
        policySource: "https://developer.chrome.com/docs/webstore/api/v1",
      });
    });
  }

  if (isChromeManifestPath(file)) {
    manifestFiles.push({ file, content });
  }
  if (/(^|\/)package\.json$/i.test(file)) {
    packageFiles.push({ file, content });
  }
}

function manifestFinding({
  ruleId,
  severity,
  file,
  evidence,
  title,
  impact,
  recommendation,
  confidence = "deterministic",
}) {
  addFinding({
    ruleId,
    ruleVersion: "1.0.0",
    severity,
    confidence,
    file,
    evidence,
    title,
    impact,
    recommendation,
    policySource,
  });
}

function scanManifestFile(file, content) {
  let localPermissionPenalty = 0;

  try {
    const manifest = JSON.parse(content);

    if (manifest.manifest_version !== 3) {
      manifestFinding({
        ruleId: "MANIFEST_VERSION",
        severity: "blocker",
        file,
        evidence: `manifest_version=${String(manifest.manifest_version)}`,
        title: "Chrome-target manifest is not MV3",
        impact: "The extension cannot use the current Chrome Web Store MV3 release path.",
        recommendation: "Migrate the Chrome target to Manifest V3 before release.",
      });
    }

    const risky = new Map([
      ["tabs", 6],
      ["history", 10],
      ["cookies", 10],
      ["webRequest", 8],
      ["webRequestBlocking", 14],
      ["management", 14],
      ["debugger", 18],
    ]);

    for (const permission of manifest.permissions || []) {
      const penalty = risky.get(permission);
      if (!penalty) continue;
      localPermissionPenalty += penalty;
      manifestFinding({
        ruleId: "SENSITIVE_PERMISSION",
        severity: penalty >= 14 ? "high" : "medium",
        file,
        evidence: permission,
        title: `Sensitive permission requested: ${permission}`,
        impact:
          "Broader privileges increase user trust requirements and can create additional Chrome Web Store scrutiny.",
        recommendation:
          "Confirm this permission is required by shipped functionality; remove or narrow it if it is not.",
      });
    }

    if ((manifest.host_permissions || []).includes("<all_urls>")) {
      localPermissionPenalty += 18;
      manifestFinding({
        ruleId: "ALL_URLS_PERMISSION",
        severity: "high",
        file,
        evidence: "<all_urls>",
        title: "Extension requests access to all websites",
        impact:
          "Very broad host access increases privacy exposure, permission-warning friction, and store-review risk.",
        recommendation:
          "Replace <all_urls> with the smallest explicit host allowlist required by the product.",
      });
    }

    if (
      (manifest.content_scripts || []).some((script) =>
        (script.matches || []).includes("<all_urls>"),
      )
    ) {
      localPermissionPenalty += 10;
      manifestFinding({
        ruleId: "CONTENT_SCRIPT_ALL_URLS",
        severity: "high",
        file,
        evidence: "content_scripts.matches=<all_urls>",
        title: "Content script runs on all websites",
        impact:
          "This creates a large execution and privacy surface and makes least-privilege justification difficult.",
        recommendation:
          "Scope content-script matches to only the sites and paths required by the product.",
      });
    }

    const externalMatches = manifest.externally_connectable?.matches || [];
    if (
      externalMatches.some(
        (match) => match === "<all_urls>" || match === "*://*/*",
      )
    ) {
      localPermissionPenalty += 12;
      manifestFinding({
        ruleId: "EXTERNALLY_CONNECTABLE_WILDCARD",
        severity: "high",
        file,
        evidence: externalMatches.join(", ").slice(0, 300),
        title: "External messaging is exposed to wildcard origins",
        impact:
          "A broad external messaging boundary can expose privileged extension functionality to untrusted callers.",
        recommendation:
          "Restrict externally_connectable.matches to an explicit trusted-origin allowlist.",
      });
    }

    if (
      (manifest.web_accessible_resources || []).some(
        (entry) =>
          (entry.resources || []).includes("*") &&
          (entry.matches || []).some(
            (match) => match === "<all_urls>" || match === "*://*/*",
          ),
      )
    ) {
      manifestFinding({
        ruleId: "WEB_ACCESSIBLE_ALL_RESOURCES",
        severity: "high",
        file,
        evidence: "resources=* with wildcard matches",
        title: "All packaged resources are web-accessible",
        impact:
          "Over-broad resource exposure increases the extension's observable and interactable attack surface.",
        recommendation:
          "Expose only the exact packaged files and origins that require web access.",
      });
    }

    const csp =
      typeof manifest.content_security_policy === "string"
        ? manifest.content_security_policy
        : manifest.content_security_policy?.extension_pages;

    if (csp?.includes("'unsafe-eval'")) {
      manifestFinding({
        ruleId: "EXTENSION_CSP_UNSAFE_EVAL",
        severity: "blocker",
        file,
        evidence: "'unsafe-eval'",
        title: "Extension CSP permits unsafe evaluation",
        impact:
          "Release rejection risk and a materially weaker code-execution boundary.",
        recommendation:
          "Remove 'unsafe-eval' and use packaged, statically analyzable code.",
      });
    }
  } catch {
    manifestFinding({
      ruleId: "MANIFEST_PARSE",
      severity: "blocker",
      file,
      title: "Chrome-target manifest cannot be parsed",
      impact: "The browser cannot reliably consume this extension manifest.",
      recommendation: "Fix the JSON syntax before release validation.",
    });
  }

  permissionPenalty = Math.max(permissionPenalty, Math.min(localPermissionPenalty, 75));
}

function dependencyFinding({
  ruleId,
  severity,
  file,
  evidence,
  title,
  impact,
  recommendation,
  confidence = "deterministic",
  reference = "https://docs.npmjs.com/cli/v11/configuring-npm/package-json",
}) {
  addFinding({
    ruleId,
    ruleVersion: "1.0.0",
    severity,
    confidence,
    file,
    evidence:
      evidence === undefined ? undefined : redactEvidence(evidence, 500),
    title,
    impact,
    recommendation,
    policySource: reference,
  });
}

function isPinnedGitSpec(spec) {
  if (!/(?:^git\+|^git:|^github:|github\.com)/i.test(spec)) return true;
  const fragment = spec.split("#")[1] ?? "";
  return /^[0-9a-f]{40}$/i.test(fragment);
}

function scanDependencyFiles() {
  for (const candidate of packageFiles) {
    let pkg;
    try {
      pkg = JSON.parse(candidate.content);
    } catch {
      dependencyFinding({
        ruleId: "PACKAGE_JSON_PARSE",
        severity: "high",
        file: candidate.file,
        title: "package.json cannot be parsed",
        impact: "Build reproducibility and dependency verification are blocked.",
        recommendation: "Fix package.json syntax before release validation.",
      });
      continue;
    }

    const dir =
      path.posix.dirname(candidate.file) === "."
        ? ""
        : path.posix.dirname(candidate.file);
    if (!lockDirs.has(dir)) {
      dependencyFinding({
        ruleId: "DEPENDENCY_LOCKFILE_MISSING",
        severity: "medium",
        file: candidate.file,
        title: "Dependency lockfile not detected",
        impact:
          "Builds can resolve different transitive dependency versions over time, weakening reproducibility and incident analysis.",
        recommendation:
          "Commit the package-manager lockfile used by CI/release builds and use frozen/immutable install mode.",
        reference:
          "https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json",
      });
    }

    for (const lifecycle of ["preinstall", "install", "postinstall", "prepare"]) {
      const script = pkg.scripts?.[lifecycle];
      if (
        typeof script === "string" &&
        /(?:\bcurl\b|\bwget\b|Invoke-WebRequest|Invoke-RestMethod|https?:\/\/)/i.test(
          script,
        )
      ) {
        dependencyFinding({
          ruleId: "INSTALL_SCRIPT_NETWORK",
          severity: "high",
          confidence: "high",
          file: candidate.file,
          evidence: `${lifecycle}: ${script}`,
          title: `Network-capable ${lifecycle} lifecycle script`,
          impact:
            "Install-time network execution expands the software supply-chain attack surface before the application build starts.",
          recommendation:
            "Remove install-time downloads where possible; otherwise pin and verify fetched artifacts and restrict CI egress.",
        });
      }
    }

    for (const group of [
      pkg.dependencies,
      pkg.devDependencies,
      pkg.optionalDependencies,
    ]) {
      for (const [name, raw] of Object.entries(group ?? {})) {
        if (typeof raw !== "string") continue;
        if (/^(?:git\+)?http:\/\//i.test(raw)) {
          dependencyFinding({
            ruleId: "INSECURE_DEPENDENCY_SOURCE",
            severity: "high",
            file: candidate.file,
            evidence: `${name}: ${raw}`,
            title: `Dependency ${name} uses an insecure source`,
            impact:
              "Dependency content can be intercepted or replaced in transit before build execution.",
            recommendation:
              "Use the package registry or an HTTPS/SSH source pinned to an immutable revision.",
          });
        } else if (!isPinnedGitSpec(raw)) {
          dependencyFinding({
            ruleId: "UNPINNED_GIT_DEPENDENCY",
            severity: "medium",
            file: candidate.file,
            evidence: `${name}: ${raw}`,
            title: `Git dependency ${name} is not commit-pinned`,
            impact:
              "The same dependency declaration can resolve to different code without a package.json change.",
            recommendation:
              "Pin Git dependencies to a full immutable commit SHA and retain a lockfile.",
          });
        }
      }
    }
  }
}

function scanPermissionConsistency(activeManifests) {
  // Without a usable manifest there is no declared-permission baseline.
  // Do not accuse web apps or documentation repositories of missing privileges.
  if (activeManifests.length === 0) return;
  const required = new Set();
  const optional = new Set();
  for (const candidate of activeManifests) {
    try {
      const manifest = JSON.parse(candidate.content);
      for (const value of manifest.permissions || []) required.add(value);
      for (const value of manifest.optional_permissions || []) optional.add(value);
    } catch {
      // Manifest parse errors are already reported by scanManifestFile.
    }
  }

  const declared = new Set([...required, ...optional]);
  const source = extensionSourceChunks.join("\n");
  const apiPermissions = new Map([
    ["history", ["chrome.history", "browser.history"]],
    ["cookies", ["chrome.cookies", "browser.cookies"]],
    ["webRequest", ["chrome.webRequest", "browser.webRequest"]],
    ["webRequestBlocking", ["chrome.webRequest", "browser.webRequest"]],
    ["management", ["chrome.management", "browser.management"]],
    ["debugger", ["chrome.debugger", "browser.debugger"]],
    ["privacy", ["chrome.privacy", "browser.privacy"]],
    ["downloads", ["chrome.downloads", "browser.downloads"]],
    ["bookmarks", ["chrome.bookmarks", "browser.bookmarks"]],
    ["notifications", ["chrome.notifications", "browser.notifications"]],
    ["scripting", ["chrome.scripting", "browser.scripting"]],
  ]);
  const privileged = new Set([
    "history",
    "cookies",
    "webRequest",
    "webRequestBlocking",
    "management",
    "debugger",
    "privacy",
  ]);

  for (const [permission, needles] of apiPermissions) {
    const used = needles.some((needle) => source.includes(needle));
    if (used && !declared.has(permission) && permission !== "webRequestBlocking") {
      securityFinding({
        ruleId: "MISSING_API_PERMISSION",
        severity: "high",
        confidence: "high",
        evidence: needles.find((needle) => source.includes(needle)),
        title: `Code uses ${permission} API without matching manifest permission`,
        impact:
          "The affected feature can fail at runtime and the submitted extension may not behave as reviewed.",
        recommendation:
          `Declare the narrowest permission required for this feature, or remove obsolete ${permission} API usage.`,
      });
    }

    if (required.has(permission) && privileged.has(permission) && !used) {
      securityFinding({
        ruleId: "UNUSED_PRIVILEGED_PERMISSION",
        severity: "medium",
        confidence: "heuristic",
        evidence: permission,
        title: `Privileged ${permission} permission is not used in reviewed source`,
        impact:
          "An unnecessary privileged permission increases install-time trust cost and can create avoidable store-review scrutiny.",
        recommendation:
          "Confirm the permission is genuinely required. If not, remove it or move it to optional_permissions.",
      });
    }
  }
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
  scanPermissionConsistency(active);
}

walk(root);
scanDependencyFiles();
scanActiveManifests();

const blockerCount = findings.filter((f) => f.severity === "blocker").length;
const highCount = findings.filter((f) => f.severity === "high").length;
const mediumCount = findings.filter((f) => f.severity === "medium").length;
const rawScore = Math.max(
  0,
  100 -
    blockerCount * 55 -
    highCount * 22 -
    mediumCount * 8 -
    Math.min(permissionPenalty, 75),
);
const score = blockerCount > 0 ? Math.min(rawScore, 49) : rawScore;

const reportDir = path.join(root, ".extensionops");
fs.mkdirSync(reportDir, { recursive: true });
const reportPath = path.join(reportDir, "report.json");
fs.writeFileSync(
  reportPath,
  JSON.stringify(
    {
      schemaVersion: "2",
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

console.log(
  `ExtensionOps score: ${score}/100; findings: ${findings.length}; blockers: ${blockerCount}; high: ${highCount}; medium: ${mediumCount}`,
);
if (blockerCount > 0) process.exitCode = 2;
