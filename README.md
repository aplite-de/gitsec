# gitsec

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-orange.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)]()

**gitsec** is a modular Python CLI tool for auditing GitHub security posture at organization, repository, and local repository level.

It helps security and engineering teams review GitHub configuration, detect hardcoded secrets, identify dependency risks, and generate reports in **HTML**, **SARIF**, or **CSV** format.

---

## What gitsec does

gitsec combines three security auditing modules into one CLI workflow:

1. **Secret scanning** : detects hardcoded credentials and sensitive values.
2. **Dependency scanning** : checks project dependencies for known vulnerabilities and package risks.
3. **GitHub security checks** : audits organization and repository security settings.

The result is a consolidated report that helps teams identify security gaps, prioritize remediation, and review findings in a cleaner format.

---

## Key Features

- Audit GitHub organizations or individual repositories
- Scan local repositories for secrets and dependency risks
- Detect hardcoded secrets using `detect-secrets`
- Identify vulnerable, deprecated, or unpinned dependencies
- Review GitHub organization and repository security settings
- Generate browser-friendly **HTML reports**
- Export findings in **SARIF** for SARIF-compatible tools
- Export findings in **CSV** for further analysis
- Support GitHub Enterprise Server using `--base-url`
- Support configuration files for repeatable scans

---

## Report Output

gitsec supports the following output formats:

| Format | Purpose |
|---|---|
| **HTML** | Human-readable report with summary, filters, grouped findings, and detailed finding review |
| **SARIF** | Standard JSON-based format for security/static-analysis tooling |
| **CSV** | Lightweight tabular output for further processing or analysis |

Example:

```bash
gitsec audit-all --repo owner/repo --format html --out-folder reports
gitsec audit-all --repo owner/repo --format sarif --out-folder reports
gitsec audit-all --repo owner/repo --format html,sarif --out-folder reports
```

---

## HTML Report

The HTML report is designed for easier review of GitSec scan results.

### Header

The report header includes:

- Scanned target: repository or organization
- Generated date
- Total findings

### Summary Tab

The **Summary** tab is the main landing page and provides a high-level overview of the scan result.

It includes:

- Severity distribution with pie chart
- Finding type breakdown
- Affected repositories
- Duplicate findings
- Top 3 actions

### Top 3 Actions

The **Top 3 actions** card highlights recurring or high-priority findings.

It includes:

- Highest-severity findings first
- Repeated findings count
- Preview findings by default
- “Show all findings” to display the full related list
- “Show preview only” to return to the shortened view

### Findings Tab

The **Findings** tab contains the detailed GitSec findings.

It includes:

- Search filter
- Severity filter
- Type/check filter
- Individual finding details
- Grouping by issue
- Grouping by repository
- Default view for individual findings

### Behavior

- Summary tab is the default landing page
- Filters only affect the Findings tab
- Summary always reflects the full scan result
- Pie chart is only for visualization
- Detailed findings are shown in the Findings tab

---

## Security Modules

### 1. Secret Scanning

Secret scanning detects hardcoded secrets and credentials in the codebase using the `detect-secrets` library with custom plugins.

Examples of detected secrets:

- API keys
- Cloud provider credentials
- Database connection strings
- Private keys and certificates
- OAuth tokens
- Webhook secrets

Example:

```bash
gitsec scan-secrets --repo owner/repo --format html
gitsec scan-secrets --org myorg --format html
gitsec scan-secrets --local-repo /path/to/repo --format csv
```

---

### 2. Dependency Scanning

Dependency scanning identifies dependency-related risks using the deps.dev API.

It can detect:

- Known CVEs and security advisories
- CVSS severity scores
- Deprecated packages
- Unpinned dependencies
- Multiple ecosystems such as npm, pip, Maven, and Go

Example:

```bash
gitsec scan-dependencies --repo owner/repo --format html
gitsec scan-dependencies --org myorg --format sarif
gitsec scan-dependencies --local-repo /path/to/repo --format csv
```

---

### 3. GitHub Security Checks

Security checks audit GitHub organization and repository settings.

> Security checks require GitHub API access and are not available for local repositories.

#### Organization-level checks

- `org-mfa` : MFA requirement for organization members
- `org-sso` : SSO/SAML configuration
- `org-default-repo-permission` : default repository permissions
- `org-members-can-create-repos` : member repository creation permissions
- `org-commit-signing` : commit signing enforcement
- `org-pr-required` : pull request requirements
- `org-push-protection` : push protection
- `org-tag-deletion-protection` : tag deletion protection
- `org-secrets-scope` : organization secrets visibility and scope
- `org-runners-scope` : self-hosted runners scope and visibility
- `org-user-access` : user access patterns and permissions

#### Repository-level checks

- `repo-commit-signing` : commit signing requirement
- `repo-pr-required` : pull request requirement on default branch
- `repo-push-protection` : direct push protection on default branch
- `repo-tag-deletion-protection` : tag deletion protection
- `repo-runners-scope` : self-hosted runners scope

Example:

```bash
gitsec security-checks all-org --org myorg
gitsec security-checks all-repo --repo owner/repo
gitsec security-checks org-mfa org-sso --org myorg
gitsec security-checks repo-commit-signing repo-pr-required --repo owner/repo
```

---

## Installation

### Using pip

```bash
pip install gitsec
```

### Using pipx

```bash
pipx install gitsec
```

### For development

```bash
git clone https://github.com/yourusername/gitsec.git
cd gitsec
poetry install
```

---

## Authentication

Set a GitHub personal access token before running GitHub organization or repository scans:

```bash
export GITHUB_TOKEN=your_github_personal_access_token
```

Required token access depends on the checks you run.

Recommended scopes for classic tokens:

- `repo` : access repository data
- `read:org` : read organization data
- `admin:org` : read organization security settings

For GitHub Enterprise Server, make sure the token has equivalent permissions.

---

## Quick Start

Run a full audit on an organization:

```bash
gitsec audit-all --org your-org --format html --out-folder results
```

Run a full audit on a single repository:

```bash
gitsec audit-all --repo owner/repo --format html --out-folder results
```

Run a local repository scan:

```bash
gitsec audit-all --local-repo /path/to/repo --format html --out-folder results
```

---

## Usage

### Comprehensive audit

The `audit-all` command runs secret scanning, dependency scanning, and GitHub security checks where applicable.

```bash
# Organization
gitsec audit-all --org myorg --format html

# Single repository
gitsec audit-all --repo owner/repo --format html

# Single repository with custom branch
gitsec audit-all --repo owner/repo --branch develop --format html

# Local repository
gitsec audit-all --local-repo /path/to/repo --format html

# GitHub Enterprise Server
gitsec audit-all --org myorg --base-url https://github.mycorp.com --format html
```

---

## Configuration File

gitsec supports configuration files for repeatable scans and shared scan settings.

The tool discovers configuration files in this order:

1. `.gitsec.yml` or `gitsec.yml` in the current directory
2. `.gitsec.yml` in the home directory
3. Custom path through `--config`

Configuration files can define:

- Default targets
- Output folder
- Repository include/exclude filters
- Enabled or disabled scan modules
- Branch overrides for specific repositories

Example:

```yaml
target:
  org: my-organization

output_folder: audit-results

repositories:
  include:
    - "frontend-*"
    - "backend-api"
  exclude:
    - "*-archive"
    - "*-deprecated"
  max_count: 50
  sort_by: pushed_at

security_checks:
  enabled_modules:
    - org-mfa
    - org-sso
    - org-commit-signing

repository_overrides:
  frontend-app:
    branch: develop
    enabled_modules:
      - repo-commit-signing
      - repo-pr-required
```

CLI arguments always take precedence over configuration file settings.

See `examples/gitsec.example.yml` for a full configuration template.

---

## Example Reports

Here are examples of the HTML report views.

**Summary Overview**

![Summary Report](images/summary.png)

**Secret Scanning Results**

![Secret Findings](images/secrets.png)

**Dependency Vulnerabilities**

![Dependency Scan](images/dependencies.png)

**Security Checks**

![Security Checks](images/security_checks.png)

---

## GitHub Enterprise Server Support

All GitHub-based commands support GitHub Enterprise Server through the `--base-url` flag:

```bash
gitsec audit-all --org myorg --base-url https://github.mycorp.com --format html
```

---

## Performance

gitsec caches API responses during command execution to reduce redundant requests and avoid rate limits.

---

## Contributing

Contributions are welcome. Please feel free to submit a pull request.

---

## License

MIT