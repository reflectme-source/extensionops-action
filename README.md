# ExtensionOps Release Validation

Public deterministic validator used by ExtensionOps customer-owned GitHub Actions workflows.

- Runs on the repository owner's GitHub-hosted runner.
- Does not receive Chrome Web Store credentials.
- Produces `.extensionops/report.json` evidence.
- Exits non-zero on deterministic blockers.

The hosted ExtensionOps control plane never executes customer repository code.
