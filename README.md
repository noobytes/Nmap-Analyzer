# Nmap Analyzer

Turn nmap XML into actionable pentest reports — AI attack plans, CVE matching,
risk scoring, enumeration playbooks, command sanity checking, and optional automated
safe enumeration in one tool.

Two workflows are available:
- `legacy` keeps the original broad attack-plan and bulk execution behavior
- `iterative` adds a persistent analyst loop with structured observations, hypotheses, ranked approved validations, and per-result state updates

Model routing is also opt-in:
- no preset selected: `qwen3:30b` handles all stages (default)
- preset selected: specific workflow stages are routed automatically
- explicit `--model` and `--review-model` override the preset routing

## Features

- **Infrastructure role detection** — groups hosts by role (Web Server, Domain Controller, File Server, SQL Server, etc.)
- **120+ enumeration playbooks** — 550+ service-specific commands (Apache, IIS, Tomcat, Samba, WinRM, MSSQL, etc.)
- **CVE cross-referencing** — matches service versions against a local NVD-sourced SQLite database; ranks by relevance, CISA KEV status, and exploit type (RCE, auth bypass, privesc)
- **Risk scoring** — prioritizes findings by service criticality, CVE severity, KEV status, and host count
- **AI-enhanced suggestions** — optional per-service command suggestions via local Ollama
- **Command sanity check** — every generated command is validated by `qwen3:30b` before being shown or executed; flags target mismatches, destructive flags, noise, syntax errors, and premature brute force; auto-corrects broken syntax and suggests safer alternatives
- **Iterative analyst loop** — persistent `case_state.json`, structured facts vs hypotheses, ranked approved validation actions, and post-result state patches
- **Opt-in model presets** — `quick` and `deep` presets route each pipeline stage to the right model; explicit `--model` / `--review-model` override the preset
- **AI Network Overview** — concise scan summary injected at the top of the AI Analysis Report tab
- **AI Attack Plan / Analyst Summary** — legacy broad plan or structured iterative ranking depending on workflow
- **Safe auto-execution** — `--execute` runs safe enumeration commands only (no brute force, no exploitation); brute force commands are kept as manual suggestions
- **SSH remote execution** — `--remote-host kali@IP` runs all commands on a remote Kali box via SSH ControlMaster while Ollama stays on your local machine
- **Live Findings tab** — execution results displayed in the HTML report with Ollama synthesis of all outputs
- **Case-state persistence** — iterative workflow state can be resumed from a saved JSON file
- **Pre-flight checks** — validates tool availability and passwordless sudo before executing
- **Self-contained HTML report** — interactive tabbed report (Network Summary, Suggested Action, AI Analysis Report, Live Findings)
- **File logging** — every run writes a full debug log to `logs/run_<timestamp>.log`
- **Robust** — handles any nmap XML (empty scans, tcpwrapped services, closed ports, malformed data)

## Prerequisites

- **Python 3.10+** (tested on 3.11, 3.12, 3.14)
- **Nmap** — to generate XML scan files (`nmap -oX`)
- **Git** — to clone the repository
- **(Optional) Ollama** — for local AI suggestions (`--ai`). Must be installed manually — see [ollama.com/download](https://ollama.com/download)

## Installation

### Step 1: Clone the repository

```bash
git clone https://github.com/lzyh00ps/Nmap-Analyzer.git
cd Nmap-Analyzer
```

### Step 2: Run the setup script

```bash
python3 setup.py
```

This will automatically:
- Create a Python virtual environment (`venv/`)
- Install all dependencies (plotly, defusedxml, httpx)
- Create required data directories (`data/`, `data/nvd_feeds/`, `reports/`, `logs/`)
- Generate the `analyzer.sh` convenience script
- Verify the package installation
- Print a note on how to set up Ollama manually (optional, for `--ai`)

### Step 3 (Alternative): Manual setup

If you prefer manual installation:

```bash
python3 -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate         # Windows
pip install -r requirements.txt
mkdir -p data/nvd_feeds reports logs
```

### Step 4: Build the CVE database (recommended)

```bash
./analyzer.sh --cve-db-update
```

This downloads NVD JSON feeds and builds a local SQLite database at `data/cve_database.db`.
First run does a full import (2002–current year). Subsequent runs do incremental updates.

### Step 5: Set up Ollama (optional, for AI features)

Ollama is **not installed automatically**. If you want AI-powered suggestions (`--ai`), install it manually:

1. Download and install Ollama: https://ollama.com/download
2. Pull the default model: `ollama pull qwen3:30b`
3. Start the Ollama server: `ollama serve`

If Ollama runs on a non-default host/port, set it in `.env`:

```bash
cp .env_example .env
# Edit .env and uncomment:
# OLLAMA_HOST=http://your-host:11434
```

The `analyzer.sh` script auto-loads `.env` on startup.

## Usage

### Recommended command cheat sheet

```bash
# Basic scan analysis, no AI
./analyzer.sh scan.xml -C myproject

# AI-assisted analysis (qwen3:30b handles all stages by default)
./analyzer.sh scan.xml -C myproject --ai

# Internal assessment profile
./analyzer.sh scan.xml -C myproject --ai --profile internal

# External assessment profile
./analyzer.sh scan.xml -C myproject --ai --profile external

# quick preset — gemma4:26b for overview/result_review, qwen3:30b for everything else
./analyzer.sh scan.xml -C myproject --ai --preset quick

# deep preset — gemma4:26b for overview only, qwen3:30b for all remaining stages
./analyzer.sh scan.xml -C myproject --ai --preset deep

# Override the primary model
./analyzer.sh scan.xml -C myproject --ai --model gemma4:26b

# Override the review model only
./analyzer.sh scan.xml -C myproject --ai --preset quick --review-model gemma4:26b

# Safe iterative execution
./analyzer.sh scan.xml -C myproject --ai --execute

# Iterative execution with a batch of 2 approved steps
./analyzer.sh scan.xml -C myproject --ai --execute --workflow iterative --iterative-batch-size 2

# Resume an iterative case from a saved state file
./analyzer.sh scan.xml -C myproject --ai --execute --case-state reports/<run>/case_state.json

# Keep the original legacy execution behavior
./analyzer.sh scan.xml -C myproject --ai --execute --workflow legacy

# Run execution remotely from a Kali box over SSH
./analyzer.sh scan.xml -C myproject --ai --execute --remote-host kali@192.168.1.100

# Update the CVE database and analyze in one run
./analyzer.sh --cve-db-update scan.xml -C myproject --ai
```

### Basic analysis (playbooks only, no AI)

```bash
./analyzer.sh scan.xml -C myproject
```

### With AI suggestions and attack plan

```bash
# AI suggestions only (no profile — chunked per-service analysis)
./analyzer.sh scan.xml -C myproject --ai

# External pentest profile (internet-facing targets, initial access focus)
./analyzer.sh scan.xml -C myproject --ai --profile external

# Internal pentest profile (inside the network, lateral movement and AD focus)
./analyzer.sh scan.xml -C myproject --ai --profile internal
```

### Model routing and presets

If you do nothing, all stages use `qwen3:30b`. The tool does not auto-switch models by task type unless you explicitly select a preset or set model flags.

```bash
# Default behavior: qwen3:30b handles all 6 stages
./analyzer.sh scan.xml -C myproject --ai

# quick — gemma4:26b for network_overview + result_review,
#         qwen3:30b for profile_analysis, command_generation,
#         command_sanity_check, and iterative_ranking
./analyzer.sh scan.xml -C myproject --ai --preset quick

# deep  — gemma4:26b for network_overview only,
#         qwen3:30b for all remaining 5 stages
./analyzer.sh scan.xml -C myproject --ai --preset deep

# Override the preset's primary model
./analyzer.sh scan.xml -C myproject --ai --preset quick --model gemma4:26b

# Override the preset's review model
./analyzer.sh scan.xml -C myproject --ai --preset quick --review-model gemma4:26b
```

### Preset stage routing

Each preset routes the 6 pipeline stages to specific models. Stages run in order for every analysis.

| Stage | What it does |
|---|---|
| `network_overview` | 2-3 sentence plain-English scan summary injected at the top of the AI Analysis Report tab |
| `profile_analysis` | Full attack plan using the external or internal profile prompt |
| `command_generation` | Per-service enumeration command suggestions |
| `command_sanity_check` | Validates every generated command — flags mismatches, risky flags, noise, syntax errors, premature brute force; auto-corrects or suggests safer alternatives |
| `iterative_ranking` | Ranks and reasons about candidate validation actions in the analyst loop |
| `result_review` | Classifies executed command output (useful / inconclusive / negative / timeout) |

**Stage routing by preset:**

| Stage | none (default) | `quick` | `deep` |
|---|---|---|---|
| `network_overview` | `qwen3:30b` | `gemma4:26b` | `gemma4:26b` |
| `profile_analysis` | `qwen3:30b` | `qwen3:30b` | `qwen3:30b` |
| `command_generation` | `qwen3:30b` | `qwen3:30b` | `qwen3:30b` |
| `command_sanity_check` | `qwen3:30b` | `qwen3:30b` | `qwen3:30b` |
| `iterative_ranking` | `qwen3:30b` | `qwen3:30b` | `qwen3:30b` |
| `result_review` | `qwen3:30b` | `gemma4:26b` | `qwen3:30b` |

### Preset workflows in detail

---

#### Default — no preset (`--ai` only)

One model handles all 6 stages. Simplest setup — one `ollama pull` required.

```
[network_overview]       qwen3:30b  →  scan summary
[profile_analysis]       qwen3:30b  →  full attack plan
[command_generation]     qwen3:30b  →  per-service commands
[command_sanity_check]   qwen3:30b  →  validate + correct commands
[iterative_ranking]      qwen3:30b  →  rank candidate actions
[result_review]          qwen3:30b  →  classify command output
```

```bash
./analyzer.sh scan.xml -C myproject --ai --profile external
```

---

#### `quick` — fast bookend triage + deep reasoning for the core stages

`gemma4:26b` handles the lightweight bookend tasks (scan summary and result classification).
`qwen3:30b` drives the four middle stages that require reasoning: attack planning, command
generation, sanity checking, and iterative ranking.

```
[network_overview]       gemma4:26b  →  scan summary           (fast triage)
[profile_analysis]       qwen3:30b   →  full attack plan       ← deep reasoning
[command_generation]     qwen3:30b   →  per-service commands   ← deep reasoning
[command_sanity_check]   qwen3:30b   →  validate commands      ← deep reasoning
[iterative_ranking]      qwen3:30b   →  rank candidate actions ← deep reasoning
[result_review]          gemma4:26b  →  classify output        (fast triage)
```

```bash
./analyzer.sh scan.xml -C myproject --ai --preset quick --profile external
./analyzer.sh scan.xml -C myproject --ai --preset quick --execute --workflow iterative
```

**Best for:** Balanced speed and depth. Gemma handles the routine bookends; Qwen3 reasons through everything that matters.

---

#### `deep` — maximum reasoning depth across all meaningful stages

`gemma4:26b` handles only the initial scan summary. `qwen3:30b` takes over for every
stage that influences what gets run, what gets checked, and what to do next.

```
[network_overview]       gemma4:26b  →  scan summary           (quick handoff)
[profile_analysis]       qwen3:30b   →  full attack plan       ← deep reasoning
[command_generation]     qwen3:30b   →  per-service commands   ← deep reasoning
[command_sanity_check]   qwen3:30b   →  validate commands      ← deep reasoning
[iterative_ranking]      qwen3:30b   →  rank candidate actions ← deep reasoning
[result_review]          qwen3:30b   →  classify output        ← deep reasoning
```

```bash
# Planning pass — Qwen3 writes the attack narrative and validates every command
./analyzer.sh scan.xml -C myproject --ai --preset deep --profile external

# Execution loop — Qwen3 drives ranking, sanity checks, and result review each iteration
./analyzer.sh scan.xml -C myproject --ai --preset deep --workflow iterative --execute
```

**Best for:** High-value engagements where you want Qwen3's reasoning applied at every decision point — from attack planning through live result interpretation.

### Command Sanity Check

The `command_sanity_check` stage runs automatically whenever `--ai` is enabled.
It inspects every generated command (playbook + AI) before it is shown or executed.

**What it checks:**

| Issue type | Example |
|---|---|
| `target_mismatch` | Windows SMB tools against a Linux host; AD commands on non-domain systems; web fuzzing against a non-web port |
| `destructive` | `-T5` timing; hydra with no rate limit against AD; excessive thread counts |
| `noise` | Loud scans in external/stealth context; brute force during initial recon; NSE scripts that trigger EDR/SIEM |
| `syntax` | Wrong flag names; incompatible arguments; malformed command structure |
| `bruteforce` | Password spraying before enumeration; hydra/medusa before version detection |

**What it outputs per command:**

```json
{
  "approved": false,
  "risk_level": "medium",
  "issues": [{"type": "noise", "message": "-T5 is too aggressive for most engagements"}],
  "corrected_command": "",
  "safer_alternative": "nmap -T3 -Pn -sV --top-ports 1000 TARGET",
  "operator_warning": "Use -T3 instead of -T5",
  "confidence": 0.92
}
```

**Behavior rules:**
- `approved=true` → command passes through unchanged
- `corrected_command` provided → broken syntax is auto-corrected in the suggestion list
- `safer_alternative` provided → appended as an additional suggestion alongside the original
- Warnings surface in `findings.txt` and the HTML report under **Sanity Check Warnings**
- If the model fails or returns invalid JSON → safe pass-through, original commands unchanged
- Never silently drops a command without explanation

### Auto-execute safe enumeration commands

```bash
# Analyze + execute enumeration commands locally (prompts for confirmation)
./analyzer.sh scan.xml -C myproject --ai --execute

# Skip confirmation prompt
./analyzer.sh scan.xml -C myproject --ai --execute --no-confirm

# Limit to 20 commands, 90s timeout per command
./analyzer.sh scan.xml -C myproject --ai --execute --max-exec-commands 20 --exec-timeout 90
```

### Iterative analyst workflow

When `--ai` and `--execute` are enabled together, the default workflow becomes `iterative`.
In this mode the tool:

1. builds a persistent case state from parsed scan data
2. ranks approved validation actions from playbooks plus AI suggestions
3. executes only the top approved step by default
4. interprets the result with a second structured prompt
5. patches `case_state.json` and repeats until it runs out of useful approved steps or hits `--max-exec-commands`

```bash
# Default iterative mode when both --ai and --execute are enabled
./analyzer.sh scan.xml -C myproject --ai --execute

# Explicit iterative mode with a tiny batch of 2 steps per loop
./analyzer.sh scan.xml -C myproject --ai --execute --workflow iterative --iterative-batch-size 2

# Resume a previous iterative run from its saved state
./analyzer.sh scan.xml -C myproject --ai --execute \
  --case-state reports/myproject_20260424_120000/case_state.json

# Keep the original bulk execution behavior
./analyzer.sh scan.xml -C myproject --ai --execute --workflow legacy
```

The iterative workflow preserves the current safety model:
- only allowlisted safe enumeration commands are auto-executed
- manual-only and blocked actions are never auto-run
- scope validation and missing-tool checks still apply
- brute force, exploitation, credential attacks, and destructive testing are not auto-executed

### Execute on a remote Kali box via SSH

Run Nmap Analyzer on your local Mac with Ollama running locally, but execute all enumeration commands on a remote Kali Linux box:

```bash
# Using SSH agent / default key
./analyzer.sh scan.xml -C myproject --ai --execute --remote-host kali@192.168.1.100

# Using a specific key file
./analyzer.sh scan.xml -C myproject --ai --execute \
  --remote-host kali@192.168.1.100 \
  --remote-key ~/.ssh/kali_key \
  --remote-port 22
```

### Update CVE database + analyze in one command

```bash
./analyzer.sh --cve-db-update scan.xml -C acme --ai
```

### Run directly (without analyzer.sh)

```bash
venv/bin/python3 nmap_analyzer.py scan.xml -C myproject --ai
```

### All available options

```
usage: nmap_analyzer.py [-h] [-C PROJECT] [--ai [PROVIDER]]
                        [--preset {quick,deep}]
                        [--profile {external,internal}] [--model AI_MODEL]
                        [--review-model REVIEW_MODEL] [--ai-key AI_KEY]
                        [--ai-timeout AI_TIMEOUT]
                        [--max-ai-commands MAX_AI_COMMANDS] [--cve-db-update]
                        [--cve-rebuild]
                        [--cve-update-mode {auto,full,incremental}]
                        [--cve-force-download] [--nvd-api-key NVD_API_KEY]
                        [--min-cvss MIN_CVSS] [--execute]
                        [--exec-timeout EXEC_TIMEOUT]
                        [--max-exec-commands MAX_EXEC_COMMANDS]
                        [--workflow {iterative,legacy}]
                        [--iterative-batch-size ITERATIVE_BATCH_SIZE]
                        [--host-batch-size HOST_BATCH_SIZE]
                        [--min-action-value MIN_ACTION_VALUE]
                        [--max-noise-streak MAX_NOISE_STREAK]
                        [--no-confirm] [--case-state CASE_STATE]
                        [--remote-host USER@HOST] [--remote-key PATH]
                        [--remote-port REMOTE_PORT] [--playbooks PLAYBOOKS]
                        [--wordlist PATH]
                        [--log-level {DEBUG,INFO,WARNING,ERROR}] [--debug]
                        [scan ...]
```

#### AI options

| Flag | Default | Description |
|------|---------|-------------|
| `--ai [PROVIDER]` | — | Enable AI via local Ollama |
| `--preset {quick,deep}` | — | Enable opt-in stage-based model routing |
| `--profile {external,internal}` | — | Engagement profile for attack plan (requires `--ai`) |
| `--model <model>` | `qwen3:30b` | Override the primary AI model |
| `--review-model <model>` | — | Override the result-review model |
| `--ai-timeout <secs>` | `10` | Ollama **connection** timeout. Generation itself has no timeout — the model runs until done. |
| `--max-ai-commands <n>` | `8` | Max AI-generated commands per service |

`--ai-model` is still accepted as a backward-compatible alias for `--model`.

#### Execution options

| Flag | Default | Description |
|------|---------|-------------|
| `--execute` | off | Execute safe enumeration commands (prompts for confirmation) |
| `--exec-timeout <secs>` | `60` | Per-command timeout during execution |
| `--max-exec-commands <n>` | `30` | Max commands to auto-execute |
| `--workflow {iterative,legacy}` | auto | Workflow selection. Auto = iterative when `--ai` and `--execute` are both enabled, else legacy |
| `--iterative-batch-size <n>` | `1` | Max approved commands per iterative loop (capped at 3) |
| `--host-batch-size <n>` | `5` | Max concurrent hosts per SSH batch (limits tmux windows opened per iteration) |
| `--min-action-value <score>` | `0.0` | Skip candidates scored below this expected_value (0–10, 0 = disabled) |
| `--max-noise-streak <n>` | `6` | Stop loop early after N consecutive noise/inconclusive results (auto-set to 10 for internal, 4 for external) |
| `--no-confirm` | off | Skip the confirmation prompt before executing |
| `--case-state <path>` | report dir | Save or resume iterative workflow state |
| `--remote-host USER@HOST` | — | Run commands on a remote host via SSH |
| `--remote-key <path>` | — | SSH private key path (default: SSH agent / default key) |
| `--remote-port <port>` | `22` | SSH port for remote host |

#### CVE database options

| Flag | Default | Description |
|------|---------|-------------|
| `--cve-db-update` | — | Build/update local CVE database from NVD API |
| `--cve-rebuild` | off | Drop and rebuild CVE tables before importing |
| `--cve-update-mode` | `auto` | `auto`, `full`, or `incremental` |
| `--cve-force-download` | off | Re-fetch full window ignoring last-update timestamp |
| `--nvd-api-key <key>` | — | NVD API key for ~10× faster downloads (free at nvd.nist.gov) |
| `--min-cvss <score>` | `0.0` | Only store CVEs at or above this CVSS score |

#### Other options

| Flag | Default | Description |
|------|---------|-------------|
| `-C, --project <name>` | — | Project name — reports go to `reports/<name>_<timestamp>/` |
| `--playbooks <path>` | `data/enumeration_playbooks.json` | Custom playbooks file |
| `--wordlist <path>` | — | Wordlist for web content fuzzing (ffuf, feroxbuster, etc.). Defaults to common.txt |
| `--log-level` | `INFO` | `DEBUG`, `INFO`, `WARNING`, or `ERROR` |
| `--debug` | off | Shortcut for `--log-level DEBUG` |

## Output

Reports are saved to `reports/<project>_<timestamp>/`:

| File | Description |
|------|-------------|
| `findings.txt` | Plain text report — all findings, commands, sanity warnings, and attack plan |
| `report.html` | Self-contained interactive HTML report |
| `ai_report.txt` | Raw AI attack plan text (when `--ai` is used) |
| `live_findings.txt` | Ollama synthesis of execution results (when `--execute --ai`) |
| `case_state.json` | Iterative workflow state file (when the iterative workflow is active) |
| `enumeration/` | Per-command output files (when `--execute` is used) |
| `logs/run_<timestamp>.log` | Full DEBUG log for every run |

The iterative report includes:
- confirmed findings
- likely findings
- ruled-out hypotheses
- dead ends
- next best approved validation and why it was chosen
- per-service observations vs hypotheses
- prior executed validations and their outcomes

Example artifacts are available in [`docs/examples/`](docs/examples/).

## Prompt Templates

The structured iterative workflow uses:
- `pentest_assistant/prompts/analysis_prompt.txt` for evidence-driven action ranking
- `pentest_assistant/prompts/result_review_prompt.txt` for post-execution result interpretation

Both prompts enforce the same rules:
- facts vs hypotheses must be separated
- CVE matches are leads, not proof
- recommend only approved validation actions
- prefer the smallest next step that reduces uncertainty most
- avoid repeating failed steps unless new evidence exists
- output strict JSON only

### HTML Report Tabs

| Tab | Description |
|-----|-------------|
| **Network Summary** | Infrastructure overview — KPI cards (hosts, ports, services, CVEs, highest CVSS), severity distribution chart, host role chart, service exposure chart, Top 10 TCP Ports table, vulnerability table with filters, top group targets, service groups, attack path indicators, and pentest checklists |
| **Suggested Action** | Per-service findings with playbook commands, AI-suggested commands, CVE matches, risk scores, and sanity check warnings |
| **AI Analysis Report** | Network overview summary + per-service exploitability assessment, Host-by-Host Analysis table, attack paths, quick wins, and cross-service correlation (requires `--ai`) |
| **Live Findings** | Execution results from `--execute` mode with Ollama synthesis of all outputs (requires `--execute`) |

#### Network Summary tab sections

| Section | Content |
|---------|---------|
| **SECTION 1 — Network Overview** | AI-generated scan summary + KPI cards |
| **SECTION 2 — Severity Distribution** | Donut chart; click a slice to filter the vulnerability table |
| **SECTION 3 — Service Exposure** | Bar chart of protocol exposure counts |
| **SECTION 3b — Top 10 TCP Ports** | Table of most-seen TCP ports with host counts and a prevalence bar |
| **SECTION 4 — Host Roles** | Bar chart of host role distribution |
| **SECTION 5 — Vulnerability Table** | Filterable/sortable CVE table (search, severity filter, exploit filter) |
| **Top Group Targets** | Hosts grouped by role + CVE profile, sorted by aggregate risk score |
| **SECTION 6 — Service Groups** | Service/version groups across all hosts with CVE hit counts |
| **SECTION 7 — Attack Path Indicators** | SMB+LDAP pivot candidates, Domain Controllers, exposed RDP, vulnerable web hosts |
| **SECTION 8 — Pentest Checklist Panel** | Role-specific pentest checklist cards |

## AI Provider

| Provider | Flag | Model (default) | Notes |
|----------|------|-----------------|-------|
| Ollama | `--ai` | `qwen3:30b` | Free, local, no API key needed |

Override the model with `--model <name>`, or use a preset to route stages automatically:

```bash
# quick — gemma4:26b for bookend stages, qwen3:30b for everything in between
./analyzer.sh scan.xml -C test --ai --preset quick

# deep  — gemma4:26b for overview only, qwen3:30b for all remaining stages
./analyzer.sh scan.xml -C test --ai --preset deep
```

## Engagement Profiles

Profiles control the AI Attack Plan analysis. Pass `--profile` alongside `--ai`.

| Profile | Flag | Focus | Use When |
|---------|------|-------|----------|
| External | `--profile external` | Internet-facing footprint, WAF/CDN detection, initial access paths from the public internet | External pentest / black-box assessment |
| Internal | `--profile internal` | Lateral movement, Active Directory, Kerberoasting, NTLM relay, privilege escalation | Internal pentest / assumed breach |

**Without `--profile`:** the attack plan falls back to chunked per-service analysis (exploitability + cross-service correlations).

## Execute Mode

`--execute` automatically runs safe enumeration commands against the scan targets after confirmation.

**What runs automatically:**
- Port scanning (nmap scripts), web probing (curl, nikto, nuclei, ffuf)
- SMB/LDAP/SNMP enumeration, SSH audit, DNS queries, service fingerprinting

**What stays as manual suggestions only (never auto-run):**
- Brute force (hydra, medusa, hashcat, etc.)
- Exploitation (sqlmap, metasploit, impacket wmiexec/psexec, etc.)

**Pre-flight checks** run before execution:
- Verifies all required tools are installed on the target system
- Checks if passwordless sudo is available (warns if not)
- Validates all target IPs are within scan scope

**SSH remote execution** (`--remote-host`):
- Opens a single SSH ControlMaster connection — all commands reuse it (no repeated handshakes)
- Ollama AI stays on your local machine; only the enumeration commands run remotely
- Each command runs in its own tmux window — survives SSH disconnects
- Watch live: `ssh kali@IP -t 'tmux attach -t nmap-<pid>'`

```bash
# Typical workflow: Mac running Ollama + Nmap Analyzer → Kali executing commands
./analyzer.sh scan.xml -C engagement --ai --profile internal \
  --execute --remote-host kali@10.10.10.5 --remote-key ~/.ssh/kali
```

## Recommended Nmap Syntax

For best results, always use `-sV` to populate product and version fields:

```bash
# Internal — fast full scan
nmap -sV -sC -T4 --open -oX scan.xml TARGET_RANGE

# External — stealthier
nmap -sV -sC -p- -T3 --open -oX scan.xml TARGET_RANGE

# UDP essentials
nmap -sU -sV --top-ports 20 --open -oX udp_scan.xml TARGET_RANGE

# Multiple files — merged by IP automatically
./analyzer.sh fast.xml full.xml -C myproject --ai
```

## CVE Database

The tool uses a local SQLite database (`data/cve_database.db`) sourced from official NVD JSON feeds.
CVEs are enriched with exploit type classification (RCE, auth bypass, privesc, SQLi, etc.) and CISA KEV status for improved ranking.

```bash
# Build from scratch (first run — downloads all feeds from 2002)
./analyzer.sh --cve-db-update

# Incremental update (only modified + recent feeds)
./analyzer.sh --cve-db-update

# Force full rebuild
./analyzer.sh --cve-db-update --cve-rebuild

# With NVD API key for ~10× faster downloads (free key)
./analyzer.sh --cve-db-update --nvd-api-key YOUR_KEY_HERE

# Direct updater script
venv/bin/python3 update_cve_db.py --mode full --rebuild
venv/bin/python3 update_cve_db.py --mode incremental
```

The tool auto-detects whether to run a full or incremental import based on whether the DB exists.

## How It Works

```
1. Nmap XML              → Parse hosts, services, versions
2. Role Detection        → Classify hosts (Web, DC, SQL, File Server, etc.)
3. Service Grouping      → Group identical services across hosts
4. CVE Lookup            → Match versions against local NVD database
                            (ranked by CVSS, CISA KEV status, exploit type)
5. Playbook Match        → Select enumeration commands from 120+ playbooks
6. AI Commands           → (Optional) Generate additional commands per service
7. Command Sanity Check  → (Optional) Validate every command before surfacing:
                            - flag target mismatches, destructive options, noise
                            - auto-correct broken syntax
                            - suggest safer/quieter alternatives
                            - surface warnings in report
8. Risk Scoring          → Prioritize by criticality, CVEs, host count
9. AI Attack Plan        → (Optional) Network overview + comprehensive analysis:
                            --profile external: internet-facing footprint, initial access
                            --profile internal: lateral movement, AD chains, privesc
                            (no profile): chunked per-service exploitability + cross-service summary
10. Execute             → (Optional) Run safe enumeration commands locally or via SSH
                           Brute force / exploitation kept as manual suggestions only
11. Live Findings       → (Optional) Ollama synthesizes all execution outputs into a verdict
12. Report              → HTML dashboard + text findings + per-command output files
```

## Project Structure

```
Nmap-Analyzer/
├── analyzer.sh                    # Entry point script (auto-loads .env)
├── nmap_analyzer.py               # CLI interface
├── setup.py                       # Installation script
├── requirements.txt               # Python dependencies
├── .env_example                   # API key template
├── pentest_assistant/             # Core package
│   ├── __init__.py
│   ├── ai.py                     # AI command generation + sanity check + attack plan + synthesis
│   ├── cve.py                    # CVE database lookup (KEV + exploit type aware)
│   ├── executor.py               # Safe execution engine + SSH ControlMaster
│   ├── models.py                 # Data models (Service, Host, Finding, SanityCheckResult, etc.)
│   ├── parser.py                 # Nmap XML parser
│   ├── pipeline.py               # Main analysis pipeline
│   ├── playbooks.py              # Enumeration playbook matcher
│   ├── providers.py              # AI provider abstraction (Ollama) + stage routing
│   ├── reporting.py              # HTML + text report generation
│   ├── role_detection.py         # Host role classification
│   └── prompts/                  # Structured prompt templates for iterative workflow
├── data/
│   └── enumeration_playbooks.json # 120+ service playbooks
├── logs/                          # Auto-created; run_<timestamp>.log per run
├── reports/                       # Auto-created; one subfolder per run
├── tests/
│   ├── test_assistant.py
│   ├── test_command_sanity_check.py
│   ├── test_cve_updater.py
│   ├── test_dashboard.py
│   ├── test_iterative_workflow.py
│   ├── test_model_routing.py
│   └── test_reporting.py
└── update_cve_db.py               # NVD feed downloader + importer
```

## Offline Operation

After the initial CVE feed download:
- Scan analysis works fully offline using `data/cve_database.db`
- AI features (Ollama) run fully locally — no network access required
- `--execute` with `--remote-host` only needs SSH access to the remote box

## Running Tests

```bash
./venv/bin/python -m unittest discover tests/ -v
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `ModuleNotFoundError` | Run `python3 setup.py` or `pip install -r requirements.txt` |
| `CVE database not found` | Run `./analyzer.sh --cve-db-update` |
| `Ollama unavailable` | Install from https://ollama.com/download, pull a model, run `ollama serve` |
| `Ollama model not found` | Run `ollama pull qwen3:30b` or specify another with `--model` |
| AI Analysis Report tab empty | Model is still running — no timeout on generation. Check `logs/` for errors. |
| `WARNING: Ollama returned an empty response` | Model ran out of token budget. Use `--model` to switch to a smaller/faster model, or check Ollama logs. |
| `stream idle timeout` | Fixed in current version (`read=None` on streaming). Update your copy. |
| SSH connection refused | Ensure `sshd` is running on the remote host: `sudo systemctl start ssh` |
| Tool not found on remote | Install missing tools on the Kali box, e.g. `sudo apt install ffuf` |
| Sudo password required | Add `kali ALL=(ALL) NOPASSWD: ALL` to `/etc/sudoers.d/` on remote box |
| `Permission denied: analyzer.sh` | Run `chmod +x analyzer.sh` |
| Reports not generated | Ensure `reports/` directory exists: `mkdir -p reports` |

## License

MIT
