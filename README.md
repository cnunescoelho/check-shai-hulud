## Step 2: Audit GitHub & CI/CD Logs

If you use GitHub, check for the following:

- Repository Changes: Look for new public repositories named `Shai-Hulud` or `Shai-Hulud Migration` in your account.

- Suspicious Commits: Check for branches named `dependabout/**` (a play on dependabot) containing `format-check.yml`.

- Workflow Artifacts: Check for GitHub Action artifacts named `format-results`, which may contain stolen secrets.

## Step 3: Check for Affected Packages 

Review your `package-lock.json` or `yarn.lock` files for known compromised dependencies, particularly around the
April 29, 2026, or May 2026 attack windows.
