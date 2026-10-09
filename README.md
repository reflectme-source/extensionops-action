# ExtensionOps Release Validation

**Deterministic preflight checks for Chrome and other browser-extension releases.** Run validation in the repository's own GitHub Actions runner, then inspect a JSON evidence report before shipping.

[Run a free public-repository scan](https://extensionops.dev/#scan) · [How it works](https://extensionops.dev/) · [Security model](https://extensionops.dev/security)

## Why use it?

Browser-extension releases can be blocked by deprecated Chrome Web Store endpoints, risky manifest patterns, missing permissions, or release-workflow configuration. ExtensionOps checks supported signals in source files and reports which checks ran, without claiming a Chrome Web Store approval.

- **Runs on your runner.** The hosted ExtensionOps service does not execute customer code.
- **No publishing credentials required.** This action does not receive your Chrome Web Store credentials.
- **Evidence you can review.** Output: `.extensionops/report.json`, with findings and source locations.
- **Deterministic release gate.** Exit code `2` when a blocker is found. Other findings are reported separately.

## Quick start

Add `.github/workflows/extension-release-check.yml` to your extension repository:

```yaml
name: Extension release checks
on:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  extension-release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Validate extension release
        id: extensionops
        uses: reflectme-source/extensionops-action@v1.0.1
        # For supply-chain pinning, replace the tag with the immutable release commit SHA.
        with:
          manifest-path: manifest.json # Optional; omit for auto-discovery.
      - name: Save release evidence
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: extensionops-release-evidence
          path: .extensionops/report.json
          if-no-files-found: warn
```

**Version note:** Use the published `v1.0.1` tag, or pin an audited release commit SHA for stronger supply-chain guarantees. The action does not publish to any browser store.

## Inputs and outputs

| Name | Direction | Description |
| --- | --- | --- |
| `manifest-path` | Input | Optional path to `manifest.json`; leave blank for auto-discovery. |
| `score` | Output | Release Confidence Score for checks executed by this action. |
| `report` | Output | Relative report path: `.extensionops/report.json`. |

The report includes its schema version, generation time, scanned file count, manifest detection, score and findings. Missing checks do **not** count as passed validation. The score is not a store approval or general code security certification.

## What the action does not do

It does not submit or publish an extension, access your publisher identity, merge pull requests, replace unit/browser tests, or guarantee Chrome Web Store acceptance.

For an additional free remote **static** inspection, paste the public GitHub repository at [extensionops.dev](https://extensionops.dev/#scan). If a deterministic remediation is verified and supported, ExtensionOps offers a **$99 one-time Fix** including a reviewable pull request and validation evidence. [Pricing and scope](https://extensionops.dev/pricing).

## Related guides

- [Chrome Web Store API V1 to V2 migration checklist](https://extensionops.dev/guides/chrome-web-store-api-v1-v2)
- [Google Chrome Web Store API V1 reference and sunset](https://developer.chrome.com/docs/webstore/api/v1)
- [Google Chrome Web Store API V2 usage](https://developer.chrome.com/docs/webstore/using-api)

## Validator regression tests

Run `node --test test/validator.test.mjs` to check real publishing-script detection and suppress reference-only examples.

## License

MIT. See [LICENSE](./LICENSE).
