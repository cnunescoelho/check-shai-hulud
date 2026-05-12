# Checking for Shai Hulud (Claude generated scanner)

To check for infection by the Mini Shai-Hulud npm worm (last updated May 2026), you should immediately
audit your development environment for specific malicious files, unexpected network activity, and suspicious
GitHub activity.

This worm acts as a "dead man's switch," meaning simply revoking tokens immediately can trigger a destructive
`rm -rf ~/ command`.

## Step 1: Check for Known Malicious Files (Immediate Action)

Scan your machine and projects for these indicators:

- Files: Look for `router\_init.js`, `setup.mjs`, or `format-check.yml` in your package roots or within
`.github/workflows/`.

- Directories: Search for `.claude/` or `.vscode/ directories`.

- Contents: Inside `.vscode/tasks.json` or `.claude/settings.json`, look for references to `.claude/setup.mjs` or
`SessionStart` hooks.

- Persistence: Search for a daemon called `gh-token-monitor` on your development machine.

## Step 2: Audit GitHub & CI/CD Logs

If you use GitHub, check for the following:

- Repository Changes: Look for new public repositories named `Shai-Hulud` or `Shai-Hulud Migration` in your account.

- Suspicious Commits: Check for branches named `dependabout/**` (a play on dependabot) containing `format-check.yml`.

- Workflow Artifacts: Check for GitHub Action artifacts named `format-results`, which may contain stolen secrets.

## Step 3: Check for Affected Packages 

Review your `package-lock.json` or `yarn.lock` files for known compromised dependencies, particularly around the
April 29, 2026, or May 2026 attack windows.
