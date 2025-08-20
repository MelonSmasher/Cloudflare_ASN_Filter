# Cloudflare ASN Filter

Cloudflare ASN Filter automates creation and synchronization of Cloudflare WAF Custom Rules from a CSV of Autonomous System Numbers (ASNs). Each ASN row specifies whether it is enabled and which action Cloudflare should take for requests originating from that ASN.

The workflow is designed to be triggered by Git commits via a Jenkins pipeline. Locally, you can run the same scripts with a `.env` file.

## Key Features

- Generate Cloudflare rule expressions from an ASN CSV using a template.
- Support an explicit `action` column per ASN:
  - `js_challenge`
  - `managed_challenge`
  - `interactive_challenge` (mapped to Cloudflare action `challenge`)
  - `block`
- Enforce no `skip` action. Disable an ASN using the `enable` column instead.
- Last-wins semantics when an ASN appears multiple times (the final row determines both `enable` and `action`).
- Generate separate rule files per action: `rules/rule-<action>-<N>.wf`.
- Sync only the managed rules to Cloudflare and preserve all manual rules.
- Generates multiple rules per action if necessary to stay within Cloudflare's character limit.

## Repository Layout

- `scripts/validate_asn_csv.py` — Validates CSV schema/values and prints a summary.
- `scripts/generate_rules.py` — Builds per-action rule files from CSV and a template.
- `scripts/sync_rules.py` — Syncs local rule files to Cloudflare WAF Custom Rules.
- `scripts/util_env.py` — Small helper to load `.env` (for local dev) and parse env vars.
- `rule-template.example.wf` — Example rule expression template containing the token `{%ASNS%}`.
- `rule-template.wf` — Rule expression template containing the token `{%ASNS%}` (copy `rule-template.example.wf` to `rule-template.wf` and modify as needed) CI populates this.
- `asn.csv` — The primary input CSV (ignored by Git; CI populates it).
- `asn_db.csv` — The database of ASNs, names, enable, and actions. A copy of this is used by CI and for local testing. You can also copy this to `asn.csv` and modify `asn.csv` for for your own use allowing you to have a decent starting point.
- `rules/` — Output directory for generated rule files (cleaned and re-populated on each generation).
- `Jenkinsfile` — CI pipeline that runs on repository updates.

## CSV Format

Header columns (order not important):

- `ASN` — Integer ASN (e.g., `13335` NOT `AS13335`).
- `Name` — Descriptive name (informational only; not used in expressions).
- `enable` — `TRUE` or `FALSE` (case-insensitive). Only `TRUE` rows are used for generation.
- `action` — One of: `js_challenge`, `managed_challenge`, `interactive_challenge`, `block`.

Notes:

- If an ASN appears multiple times, the last row in the file wins for both `enable` and `action`.
- Rows with invalid `enable` values are ignored by generation. Enabled rows must have a valid `action`.
- `interactive_challenge` is mapped to Cloudflare’s `challenge` action at sync time.
- There is no `skip` action; use `enable=FALSE` to omit an ASN.

## Rule Template

`rule-template.wf` must include the exact placeholder token `{%ASNS%}`. At generation time, the token is replaced by a set of space-separated ASNs compatible with Cloudflare’s Ruleset language.

Example template:

```txt
(ip.src.asnum in {%ASNS%} and not cf.client.bot)
```

## Generated Files

- Rule files are written to `rules/`.
- Files are split per action and by character budget: `rules/rule-<action>-<N>.wf`.
- The generator removes any existing `rules/rule-*.wf` files before writing new ones.
- Legacy support: `rules/rule-<N>.wf` is treated as `js_challenge` by the sync script.

## Managed Rules in Cloudflare

The sync script manages only rules with one of these description prefixes:

- `[AUTO] JS Challenge ASN -`
- `[AUTO] Managed Challenge ASN -`
- `[AUTO] Interactive Challenge ASN -`
- `[AUTO] Block ASN -`

All other custom rules in the `http_request_firewall_custom` phase are preserved exactly as-is. A strict prefix guard is enforced to avoid changing or removing manual rules.

## Environment Variables

These can be set in your shell or via a local `.env` file (copy `.env.example` to `.env`). In CI, Jenkins sets them as job environment variables; `.env` is not used in CI.

Shared (used by multiple scripts):

- `ASN_CSV` — Path to the input CSV. Default: `asn.csv`.
- `RULE_TEMPLATE` — Path to the rule template. Default: `rule-template.wf`.
- `RULES_DIR` — Output directory for generated rules. Default: `rules`.
- `MAX_RULE_CHARS` — Max characters per rule expression (<= 4096). Default: `4096`.

Validator options (`scripts/validate_asn_csv.py`):

- `DUP_LIMIT` — Number of duplicate entries to show in output. Default: `10`.
- `VALIDATE_JSON` — Output JSON instead of text (`true`/`false`). Default: `false`.

Sync options (`scripts/sync_rules.py`):

- `CLOUDFLARE_API_TOKEN` — API token with Zone WAF Read/Edit permissions. Required.
- `CLOUDFLARE_ZONE_ID` — Cloudflare Zone ID. Required.
- `DRY_RUN` — If `true`, only prints the plan (no changes). Default: `false`.

Dev helper (handled by `util_env.py`):

- `ENV_FILE` — Optional path to a `.env` file to load. If unset, `.env` in the CWD is loaded when present.

## Local Usage

1. Prepare `.env` (optional for local; required values must be provided for sync):

```bash
cp .env.example .env
# edit .env for your environment
```

1. Validate CSV:

```bash
python3 scripts/validate_asn_csv.py
```

1. Generate rule files:

```bash
python3 scripts/generate_rules.py
```

1. Sync to Cloudflare (preview changes first):

```bash
DRY_RUN=true python3 scripts/sync_rules.py
```

1. Apply sync:

```bash
python3 scripts/sync_rules.py
```

## CI: Jenkins Pipeline

This repository includes a `Jenkinsfile` that runs on repository updates (Git push). The pipeline stages:

1. Checkout
2. Prepare CSV (copies `asn_db.csv` to `asn.csv` for demonstration builds)
3. Validate CSV (`scripts/validate_asn_csv.py`)
4. Generate Rules (`scripts/generate_rules.py`)
5. Preflight Env (ensures Cloudflare credentials are present)
6. Sync to Cloudflare (`scripts/sync_rules.py`)
7. Archive generated rules (`rules/*.wf`)

In CI, the Jenkinsfile expects:

- A Jenkins Credentials build parameter named `CLOUDFLARE_API_TOKEN` (type: Secret Text), whose value points to a stored credential that contains the actual Cloudflare API token.
- A String parameter named `CLOUDFLARE_ZONE_ID` containing your Cloudflare Zone ID.

The pipeline binds the token with `withCredentials`, so the secret is masked and never printed.

### Jenkins Pipeline Setup

Jenkinsfile is included in the repository. It is a declarative pipeline that runs on repository updates (Git push). Use the steps below to integrate GitLab → Jenkins so pushes to the repo trigger the pipeline.

#### Prerequisites

- Jenkins with the following plugins installed: Pipeline, Git, GitLab, Credentials Binding (or EnvInject).
- Jenkins reachable from GitLab over HTTPS (recommended) and a URL you can use for webhooks (e.g., `https://jenkins.example.com`).
- A Git credential for cloning the repo (SSH key or HTTPS with Personal Access Token).

#### 1. Create Jenkins credentials for GitLab SCM

- Jenkins → Manage Jenkins → Credentials → System → Global credentials → Add Credentials
  - Option A (recommended): Kind = “SSH Username with private key”, Username = `git`, Private Key = your Jenkins deploy key
  - Option B: Kind = “Username with password”, Username = your GitLab username, Password = a Personal Access Token (PAT)

#### 2. Create and configure the Pipeline job

- Jenkins → New Item → Pipeline (or Multibranch Pipeline)
- Pipeline definition: “Pipeline script from SCM”
  - SCM: Git
  - Repository URL: `git@gitlab.example.com:project/cloudflare-asn-filter.git` (SSH) or `https://gitlab.example.com/project/cloudflare-asn-filter.git` (HTTPS)
  - Credentials: select the one from step 1
  - Branches to build: `*/main` (adjust as needed)
  - Script Path: `Jenkinsfile`
- Build Triggers:
  - Check “Build when a change is pushed to GitLab”
  - Set a Secret token and copy it for the webhook (below)
  - Optionally enable “Accept Merge Request events”
  - Note: If this trigger is not available, install/enable the GitLab plugin or use the “Generic Webhook Trigger” plugin; then adapt the webhook URL accordingly.

#### 3. Configure the GitLab webhook

- GitLab → Your project → Settings → Webhooks
- URL: `https://<jenkins-host>/project/<job-name>`
  - Example: `https://jenkins.example.com/project/cloudflare-asn-filter`
- Secret token: paste the token set in the Jenkins job trigger
- Trigger: enable “Push events” (and optionally “Merge request events”)
- Add webhook, then use “Test → Push events” to verify the Jenkins job starts

#### 4. Provide Cloudflare credentials to the job

Use a credentials parameter for the token and a string parameter for the zone ID:

1. Create the Secret Text credential that stores the Cloudflare API token
   - Jenkins → Manage Jenkins → Credentials → System → Global → Add Credentials
   - Kind: Secret text
   - Secret: your Cloudflare API token
   - ID: for example `cf-asn-token` (take note of the ID)
   - Permissions required on the token: Zone → Zone WAF → Read, Edit (scoped to your zone)

1. Add job parameters
   - Job → Configure → This project is parameterized → Add Parameter → Credentials
     - Name: `CLOUDFLARE_API_TOKEN`
     - Credentials type: Secret text
     - Default value: select the credential created above (e.g., `cf-asn-token`)
   - Add Parameter → String parameter
     - Name: `CLOUDFLARE_ZONE_ID`
     - Default value: your 32‑character Cloudflare Zone ID

Notes:

- The Jenkinsfile binds the token at runtime using `withCredentials([string(credentialsId: params.CLOUDFLARE_API_TOKEN, variable: 'CLOUDFLARE_API_TOKEN')])` so it is masked in logs.
- The “Preflight Env” stage verifies both variables without echoing their values.

#### 5. What the pipeline does on each push

1. Checkout
2. Prepare CSV/template: `cp -f asn_db.csv asn.csv` and `cp -f rule-template.example.wf rule-template.wf`
3. Validate CSV (`scripts/validate_asn_csv.py`)
4. Generate Rules (`scripts/generate_rules.py`)
5. Preflight Env (ensures Cloudflare credentials are present)
6. Sync to Cloudflare (`scripts/sync_rules.py`)
7. Archive generated rules (`rules/*.wf`)

## Example CSV Rows

```csv
ASN,Name,enable,action
13335,Cloudflare,TRUE,managed_challenge
15169,Google,TRUE,js_challenge
32934,Meta,TRUE,interactive_challenge
12389,Rostelecom,TRUE,block
```
