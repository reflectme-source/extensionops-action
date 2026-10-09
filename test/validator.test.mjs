import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const validator = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../validate.mjs");

function validate(files, manifestPath = "") {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "extensionops-action-"));
  try {
    for (const [relative, contents] of Object.entries(files)) {
      const target = path.join(workspace, relative);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.writeFileSync(target, contents, "utf8");
    }
    const execution = spawnSync(process.execPath, [validator], {
      cwd: workspace,
      env: { ...process.env, GITHUB_WORKSPACE: workspace, GITHUB_OUTPUT: "", EXTENSIONOPS_MANIFEST_PATH: manifestPath },
      encoding: "utf8",
    });
    assert.equal(execution.error, undefined, execution.stderr);
    const reportPath = path.join(workspace, ".extensionops/report.json");
    const report = fs.existsSync(reportPath) ? JSON.parse(fs.readFileSync(reportPath, "utf8")) : null;
    return { status: execution.status, report, stderr: execution.stderr };
  } finally {
    fs.rmSync(workspace, { recursive: true, force: true });
  }
}

test("does not confuse website examples with an active extension release", () => {
  const { status, report } = validate({
    "src/app/page.tsx": "const example = 'https://www.googleapis.com/chromewebstore/v1.1/items/demo/publish';",
    "src/components/LandingPreview.tsx": "const old = 'https://www.googleapis.com/chromewebstore/v1.1/items/demo';",
    "src/app/guides/migration/page.tsx": "const v1 = 'https://www.googleapis.com/chromewebstore/v1.1/items/demo';",
    "src/lib/website.ts": "const help = 'chrome.history and chrome.cookies';",
  });
  assert.equal(status, 0);
  assert.equal(report.manifestSeen, false);
  assert.deepEqual(report.findings.filter(f => ["CWS_API_V1_ENDPOINT","MISSING_API_PERMISSION"].includes(f.ruleId)), []);
});

test("detects deprecated V1 endpoint in actual release script", () => {
  const { status, report } = validate({
    "manifest.json": JSON.stringify({ manifest_version: 3, name: "Demo", version: "1.0.0", permissions: [] }),
    "scripts/publish.sh": "curl -X PUT https://www.googleapis.com/upload/chromewebstore/v1.1/items/abc",
  });
  assert.equal(status, 2);
  assert.ok(report.findings.some(f => f.ruleId === "CWS_API_V1_ENDPOINT" && f.file === "scripts/publish.sh"));
});

test("still checks API permissions when extension manifest exists", () => {
  const { status, report } = validate({
    "manifest.json": JSON.stringify({ manifest_version: 3, name: "Demo", version: "1.0.0", permissions: [] }),
    "src/content.js": "chrome.history.search({ text: '', maxResults: 5 });",
  });
  assert.equal(status, 0);
  assert.ok(report.findings.some(f => f.ruleId === "MISSING_API_PERMISSION" && f.severity === "high"));
});

test("uses a generated Plasmo manifest inside the ignored build directory", () => {
  const { status, report } = validate({
    "build/chrome-mv3-prod/manifest.json": JSON.stringify({
      manifest_version: 3, name: "Built extension", version: "1.0.0", permissions: ["history"],
    }),
    "src/content.js": "chrome.history.search({ text: '', maxResults: 5 });",
  }, "build/chrome-mv3-prod/manifest.json");
  assert.equal(status, 0);
  assert.equal(report.manifestSeen, true);
  assert.ok(!report.findings.some(f => f.ruleId === "MISSING_API_PERMISSION"));
});

test("explicit WXT output manifest takes precedence over a root manifest", () => {
  const { status, report } = validate({
    "manifest.json": JSON.stringify({ manifest_version: 3, name: "Old", version: "1.0.0", permissions: [] }),
    ".output/chrome-mv3/manifest.json": JSON.stringify({
      manifest_version: 3, name: "Built", version: "1.0.0", permissions: ["history"],
    }),
    "src/content.js": "chrome.history.search({ text: '', maxResults: 5 });",
  }, ".output/chrome-mv3/manifest.json");
  assert.equal(status, 0);
  assert.equal(report.manifestSeen, true);
  assert.ok(!report.findings.some(f => f.ruleId === "MISSING_API_PERMISSION"));
});

test("fails closed when configured manifest is missing", () => {
  const { status, report, stderr } = validate({}, "build/chrome-mv3-prod/manifest.json");
  assert.notEqual(status, 0);
  assert.equal(report, null);
  assert.match(stderr, /ENOENT/);
});

test("rejects manifest paths that escape the workspace", () => {
  const { status, report, stderr } = validate({}, "../manifest.json");
  assert.notEqual(status, 0);
  assert.equal(report, null);
  assert.match(stderr, /must stay inside/);
});

test("rejects malformed configured manifest JSON", () => {
  const { status, report, stderr } = validate({
    ".output/chrome-mv3/manifest.json": "{broken",
  }, ".output/chrome-mv3/manifest.json");
  assert.notEqual(status, 0);
  assert.equal(report, null);
  assert.match(stderr, /valid browser-extension manifest JSON/);
});
