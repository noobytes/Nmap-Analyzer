# Nmap Analyzer

Turn nmap XML into actionable pentest reports — AI attack plans, CVE matching,
risk scoring, enumeration playbooks, command sanity checking, and optional automated
safe enumeration in one tool.

The current implementation keeps the original parser, reporting, and Ollama integration,
but refactors the AI path into an explicit multi-agent workflow for authorized pentesting.

Two workflows are available:
- `legacy` keeps the original broad attack-plan and bulk execution behavior
- `iterative` adds a persistent analyst loop with structured observations, hypotheses, ranked approved validations, and per-result state updates

Model routing is also opt-in:
- no preset selected: `qwen3:30b` handles all stages (default)
- preset selected: specific workflow stages are routed automatically
- explicit `--model` and `--review-model` override the preset routing

## Multi-Agent Architecture

- `network_overview` — `gemma4:26b`; summarizes Nmap XML results, identifies live hosts, exposed services, likely roles, and obvious concerns; does not generate commands
- `profile_analysis` — `qwen3:30b`; analyzes the environment as `internal` or `external`, infers likely roles, prioritizes attack-path hypotheses, and recommends safe validation steps
- `command_generation` — `qwen3:30b`; generates safe enumeration commands only, with command, purpose, target, expected evidence, risk, auto-execution intent, and reason
- `command_sanity_check` — `qwen3:30b`; reviews every generated command and enforces strict command safety policy
- `iterative_ranking` — `qwen3:30b`; ranks the next best low-risk evidence-building actions from `case_state.json`
- `result_review` — `gemma4:26b` in `quick`, `qwen3:30b` in `deep`; classifies command output as useful, negative, inconclusive, timeout, or error
- `evidence_to_finding` — `qwen3:30b`; converts only sufficiently confirmed evidence into report-ready findings
- `report_writing` — `gemma4:26b`; improves report language for evidence-backed findings only and cannot invent new findings

Shared routing, schema, JSON repair, case-state, and safety helpers live under `pentest_assistant/core/`.

## Safety Model

- Authorized testing only.
- No exploit automation.
- No brute-force automation.
- No destructive or denial-of-service actions.
- Every generated command passes through `command_sanity_check`.
- Obvious dangerous patterns such as `rm -rf`, `shutdown`, `reboot`, `hydra`, `medusa`, `ncrack`, `sqlmap --os-shell`, `msfconsole exploit`, `hping3 flood`, and `--script dos` are blocked.
- `--script vuln` is never auto-executed.
- Only low-risk read-only enumeration commands are auto-execution candidates.
- Medium and high risk commands are forced to `manual_only`.
- JSON-returning agents are validated strictly, retried once with a correction prompt, and failures are recorded without crashing the whole run.

## Phase 2: Local RAG Knowledge Base

Phase 2 adds local retrieval-augmented generation so the assistant can use:

- pentest playbooks
- reporting language templates
- methodology notes
- service-specific validation guidance

RAG improves consistency and depth, but it is supporting context only. Retrieved knowledge is never proof. Confirmed Nmap evidence and command output always take priority. Findings still require evidence tied to a known asset.

### Local dependencies

```bash
pip install chromadb
ollama pull nomic-embed-text
```

### Knowledge ingestion

```bash
python -m pentest_assistant.rag.ingest --knowledge-dir pentest_assistant/knowledge --reset
```

### RAG-enabled analysis

```bash
./analyzer.sh scan.xml -C client --ai --preset deep --profile internal --rag
./analyzer.sh scan.xml -C client --ai --preset deep --profile internal --workflow iterative --rag --dry-run
./analyzer.sh scan.xml -C client --ai --preset deep --profile internal --workflow iterative --rag --execute --max-steps 5
```

### RAG rules

- If `--rag` is not enabled, existing behavior remains unchanged.
- If ChromaDB or Ollama embeddings are unavailable, the tool warns and continues without RAG unless `--rag-strict` is used.
- Commands surfaced from retrieved playbooks still go through `command_sanity_check`.
- Retrieved knowledge can improve analysis and reporting language, but it cannot create findings by itself.

## Phase 2B: Structured Playbook Intelligence

Phase 2B upgrades `data/enumeration_playbooks.json` into a first-class structured RAG source alongside the markdown knowledge base.

It adds:
- structured JSON playbook ingestion into ChromaDB
- per-command risk classification
- service normalization and alias mapping
- contextual retrieval for internal vs external profiles
- safer command recommendation ranking

### What it does

- Loads service entries from `data/enumeration_playbooks.json`
- Converts them into readable embedded chunks with metadata such as service, ports, context, category, aliases, and tools
- Classifies each playbook command as `low`, `medium`, `high`, `manual_only`, or `blocked`
- Prioritizes low-risk, evidence-building commands during retrieval and iterative planning

### Safety model for structured playbooks

- The JSON playbook is a knowledge source, not an auto-execution source
- Retrieved commands still require `command_sanity_check`
- `manual_only` means the command may be shown for analyst consideration but must not auto-execute
- Blocked commands are never recommended for automatic execution
- Brute force, spraying, exploitation, shell access, and destructive actions remain outside auto-execution

### CLI examples

```bash
./analyzer.sh scan.xml --rag
./analyzer.sh scan.xml --rag --profile internal
./analyzer.sh scan.xml --rag --workflow iterative --dry-run
./analyzer.sh scan.xml --rag --execute --max-steps 5
```

## Phase 2C: Safety and Workflow Unification

Phase 2C hardens the command lifecycle so safety is authoritative across legacy execution, iterative execution, playbooks, AI output, and RAG retrieval.

### What changed

- `command_sanity_check` now fails closed; if the stage fails, commands are blocked instead of approved
- one canonical command policy engine classifies risk for executor, RAG, and sanity enforcement
- direct local `shell=True` execution has been removed from command execution paths
- scope validation is mandatory before execution
- legacy `--execute` now uses the same approved `command_suggestions` lifecycle as iterative mode
- RAG knowledge is treated as untrusted reference material and wrapped in explicit prompt boundaries
- playbook and retrieved commands never bypass `command_sanity_check`

### Safety rules in practice

- No direct playbook execution
- No direct AI command execution
- No direct RAG command execution
- No auto-execution for `high`, `manual_only`, or `blocked` commands
- `medium` risk commands remain manual by default, except controlled web content discovery with bounded safety defaults
- Only in-scope, safely parsed, sanity-approved enumeration commands can auto-execute

### Example low-risk commands

```bash
curl -I http://TARGET
sslscan TARGET:443
nmap --script ssl-enum-ciphers -p 443 TARGET
```

### Example blocked or manual-only commands

```bash
hydra -L users.txt -P rockyou.txt ssh://TARGET
msfconsole exploit
nmap -sV TARGET && whoami
gobuster dir -u http://TARGET -w list.txt
```

## Web Content Discovery Strategy

Autonomous web content discovery is intentionally narrow to reduce duplicate results, target load, and review noise.

### Preferred tool order

- `ffuf` is the primary autonomous web discovery tool
- `feroxbuster` is the fallback autonomous tool only when `ffuf` is unavailable
- `gobuster` and `dirsearch` remain compatibility/manual recommendations only

### Why only one primary fuzzer

- Running multiple equivalent directory fuzzers against the same target creates duplicate findings, extra noise, and unnecessary load
- The iterative workflow tracks prior fuzzing in `case_state.json` so the same host/path is not fuzzed repeatedly unless the surface changes
- Retrieved playbook commands are normalized toward one preferred implementation where possible

### Safety defaults

- `ffuf` auto-execution is allowed only when the command is scoped, rate-limited, timeout-limited, and non-recursive
- `feroxbuster` is treated as fallback-only and must stay shallow and rate-limited
- `gobuster` and `dirsearch` are downgraded to manual recommendations by default
- All web discovery commands still pass `command_policy`, `command_sanity_check`, and `scope_guard`
- Shell chaining, metacharacters, wildcard targets, and broad fuzzing remain blocked

### Safe autonomous examples

```bash
ffuf -u http://TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -ac -mc 200,204,301,302,307,401,403 -t 10 -rate 50 -timeout 10
feroxbuster -u http://TARGET -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 10 -r --depth 1 --rate-limit 50
```

### Normalization examples

These commands may still appear in playbooks or RAG context, but autonomous orchestration will normalize or downgrade them:

```bash
gobuster dir -u http://TARGET -w WORDLIST
dirsearch -u http://TARGET -w WORDLIST
```

Normalized preferred equivalent:

```bash
ffuf -u http://TARGET/FUZZ -w WORDLIST -ac -mc 200,204,301,302,307,401,403 -t 10 -rate 50 -timeout 10
```

## Features

- **Infrastructure role detection** — groups hosts by role (Web Server, Domain Controller, File Server, SQL Server, etc.)
- **120+ enumeration playbooks** — 550+ service-specific commands (Apache, IIS, Tomcat, Samba, WinRM, MSSQL, etc.)
- **CVE cross-referencing** — matches service versions against a local NVD-sourced SQLite database; ranks by relevance, CISA KEV status, and exploit type (RCE, auth bypass, privesc)
- **Risk scoring** — prioritizes findings by service criticality, CVE severity, KEV status, and host count
- **AI-enhanced suggestions** — optional per-service command suggestions via local Ollama
- **Command sanity check** — every generated command is validated by `qwen3:30b` before being shown or executed; flags target mismatches, destructive flags, noise, syntax errors, and premature brute force; auto-corrects broken syntax and suggests safer alternatives
- **Strict JSON validation** — JSON agents are parsed strictly, retried once on malformed output, then marked failed without crashing the entire workflow
- **Iterative analyst loop** — persistent `case_state.json`, structured facts vs hypotheses, ranked approved validation actions, and post-result state patches
- **Opt-in model presets** — `quick` and `deep` presets route each pipeline stage to the right model; explicit `--model` / `--review-model` override the preset
- **AI Network Overview** — concise scan summary injected at the top of the AI Analysis Report tab
- **AI Attack Plan / Analyst Summary** — legacy broad plan or structured iterative ranking depending on workflow
- **Safe auto-execution** — `--execute` runs safe enumeration only; `--dry-run` plans without execution; `--manual-only` disables auto-execution entirely
- **Local RAG support** — optional ChromaDB-backed retrieval using Ollama embeddings (`nomic-embed-text`) with persistent local storage
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

The CVE database is not included in the repository — you build it locally from the NVD API.

**First run (full build):**

```bash
./analyzer.sh --cve-db-update
```

This pulls pentest-relevant CVEs from the NVD REST API (2018–present) and the CISA Known Exploited Vulnerabilities catalog, then writes them to `data/cve_database.db`. Only CVEs that are actionable for pentesting are stored — CISA KEV entries plus CVEs with a classifiable exploit type (RCE, auth bypass, privesc, SQLi, etc.) and CVSS ≥ 6.0.

> **Without an NVD API key** the API enforces a 5-request/30s rate limit, which adds a ~6 second pause between each batch. A full build typically takes **20–40 minutes** on a clean install.
>
> **With a free NVD API key** the limit rises to 50 requests/30s — the same build finishes in **2–4 minutes**.
>
> Get a free key at: https://nvd.nist.gov/developers/request-an-api-key

```bash
# Recommended: first run with an API key
./analyzer.sh --cve-db-update --nvd-api-key YOUR_KEY_HERE

# Or set the key as an env var so you don't have to type it each time
export NVD_API_KEY=YOUR_KEY_HERE
./analyzer.sh --cve-db-update
```

**Subsequent runs (incremental — fast):**

```bash
./analyzer.sh --cve-db-update
```

After the database exists, the same command automatically switches to incremental mode — it only fetches CVEs published or modified since the last update. This typically completes in under a minute.

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

# Dry-run iterative planning only
./analyzer.sh scan.xml -C myproject --ai --workflow iterative --dry-run

# Manual-only iterative planning
./analyzer.sh scan.xml -C myproject --ai --workflow iterative --manual-only

# Iterative execution with a batch of 2 approved steps
./analyzer.sh scan.xml -C myproject --ai --execute --workflow iterative --iterative-batch-size 2

# Cap the iterative workflow to 5 steps
./analyzer.sh scan.xml -C myproject --ai --execute --workflow iterative --max-steps 5

# Resume an iterative case from a saved state file
./analyzer.sh scan.xml -C myproject --ai --execute --case-state reports/<run>/case_state.json

# Keep the original legacy execution behavior
./analyzer.sh scan.xml -C myproject --ai --execute --workflow legacy

# Run execution remotely from a Kali box over SSH
./analyzer.sh scan.xml -C myproject --ai --execute --remote-host kali@192.168.1.100

# Update the CVE database and analyze in one run
./analyzer.sh --cve-db-update scan.xml -C myproject --ai

# Requested examples
./analyzer.sh scan.xml -C client --ai --preset quick --profile external
./analyzer.sh scan.xml -C client --ai --preset deep --profile internal --workflow iterative --dry-run
./analyzer.sh scan.xml -C client --ai --preset deep --profile internal --workflow iterative --execute --max-steps 5
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
# Default behavior: qwen3:30b handles all 8 stages
./analyzer.sh scan.xml -C myproject --ai

# quick — gemma4:26b for network_overview + result_review,
#         qwen3:30b for profile_analysis, command_generation,
#         command_sanity_check, iterative_ranking, and evidence_to_finding
./analyzer.sh scan.xml -C myproject --ai --preset quick

# deep  — gemma4:26b for network_overview only,
#         qwen3:30b for all remaining 6 stages
./analyzer.sh scan.xml -C myproject --ai --preset deep

# Override the preset's primary model
./analyzer.sh scan.xml -C myproject --ai --preset quick --model gemma4:26b

# Override the preset's review model
./analyzer.sh scan.xml -C myproject --ai --preset quick --review-model gemma4:26b
```

### Preset stage routing

Each preset routes the 8 pipeline stages to specific models. Stages run in order for every analysis.

| Stage | What it does |
|---|---|
| `network_overview` | 2-3 sentence plain-English scan summary injected at the top of the AI Analysis Report tab |
| `profile_analysis` | Full attack plan using the external or internal profile prompt |
| `command_generation` | Per-service enumeration command suggestions |
| `command_sanity_check` | Validates every generated command — flags mismatches, risky flags, noise, syntax errors, premature brute force; auto-corrects or suggests safer alternatives |
| `iterative_ranking` | Ranks and reasons about candidate validation actions in the analyst loop |
| `result_review` | Classifies executed command output (useful / inconclusive / negative / timeout) |
| `evidence_to_finding` | Converts only sufficiently confirmed evidence into report-ready findings |
| `report_writing` | Polishes wording for evidence-backed findings only; cannot invent or upgrade findings |

**Stage routing by preset:**

| Stage | none (default) | `quick` | `deep` |
|---|---|---|---|
| `network_overview` | `qwen3:30b` | `gemma4:26b` | `gemma4:26b` |
| `profile_analysis` | `qwen3:30b` | `qwen3:30b` | `qwen3:30b` |
| `command_generation` | `qwen3:30b` | `qwen3:30b` | `qwen3:30b` |
| `command_sanity_check` | `qwen3:30b` | `qwen3:30b` | `qwen3:30b` |
| `iterative_ranking` | `qwen3:30b` | `qwen3:30b` | `qwen3:30b` |
| `result_review` | `qwen3:30b` | `gemma4:26b` | `qwen3:30b` |
| `evidence_to_finding` | `qwen3:30b` | `qwen3:30b` | `qwen3:30b` |
| `report_writing` | `qwen3:30b` | `gemma4:26b` | `gemma4:26b` |

### Preset workflows in detail

---

#### Default — no preset (`--ai` only)

One model handles all 8 stages. Simplest setup — one `ollama pull` required.

```
[network_overview]       qwen3:30b  →  scan summary
[profile_analysis]       qwen3:30b  →  full attack plan
[command_generation]     qwen3:30b  →  per-service commands
[command_sanity_check]   qwen3:30b  →  validate + correct commands
[iterative_ranking]      qwen3:30b  →  rank candidate actions
[result_review]          qwen3:30b  →  classify command output
[evidence_to_finding]    qwen3:30b  →  draft confirmed findings
[report_writing]         qwen3:30b  →  improve evidence-backed wording
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
[report_writing]         gemma4:26b  →  polish report wording  (fast synthesis)
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
[report_writing]         gemma4:26b  →  polish report wording
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
- If the model fails, times out, or returns invalid JSON → fail closed; the command is blocked with `sanity_check_failed`
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

# Explicit dry-run: build recommendations, case state, and report artifacts without running commands
./analyzer.sh scan.xml -C myproject --ai --workflow iterative --dry-run

# Explicit manual-only mode: keep recommendations but never auto-execute them
./analyzer.sh scan.xml -C myproject --ai --workflow iterative --manual-only

# Explicit iterative mode with a tiny batch of 2 steps per loop
./analyzer.sh scan.xml -C myproject --ai --execute --workflow iterative --iterative-batch-size 2

# Cap the loop to five iterations even if more approved actions remain
./analyzer.sh scan.xml -C myproject --ai --execute --workflow iterative --max-steps 5

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

```text
usage: nmap_analyzer.py [-h] [-C PROJECT] [--ai [PROVIDER]] [--preset {quick,deep}]
                        [--profile {external,internal}] [--model AI_MODEL]
                        [--review-model REVIEW_MODEL] [--rag] [--rag-rebuild] [--rag-strict]
                        [--rag-top-k RAG_TOP_K] [--knowledge-dir KNOWLEDGE_DIR]
                        [--rag-db-path RAG_DB_PATH] [--embedding-model EMBEDDING_MODEL]
                        [--ai-key AI_KEY] [--ai-timeout AI_TIMEOUT]
                        [--max-ai-commands MAX_AI_COMMANDS] [--cve-db-update]
                        [--cve-rebuild] [--cve-update-mode {auto,full,incremental}]
                        [--cve-force-download] [--nvd-api-key NVD_API_KEY]
                        [--min-cvss MIN_CVSS] [--execute] [--dry-run] [--manual-only]
                        [--exec-timeout EXEC_TIMEOUT] [--max-exec-commands MAX_EXEC_COMMANDS]
                        [--max-steps MAX_STEPS] [--workflow {iterative,legacy}]
                        [--iterative-batch-size ITERATIVE_BATCH_SIZE]
                        [--host-batch-size HOST_BATCH_SIZE]
                        [--min-action-value MIN_ACTION_VALUE]
                        [--max-noise-streak MAX_NOISE_STREAK] [--no-confirm]
                        [--case-state CASE_STATE] [--remote-host USER@HOST]
                        [--remote-key PATH] [--remote-port REMOTE_PORT]
                        [--playbooks PLAYBOOKS] [--wordlist PATH]
                        [--regenerate-report REPORT_DIR] [--screenshot]
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
| `--rag` | off | Enable local RAG retrieval for AI agents |
| `--rag-rebuild` | off | Rebuild the Chroma knowledge database before analysis |
| `--rag-strict` | off | Fail hard if retrieval or embeddings are unavailable |
| `--rag-top-k <n>` | `5` | Retrieved chunks per service or prompt context |
| `--knowledge-dir <path>` | `pentest_assistant/knowledge` | Local markdown knowledge directory |
| `--rag-db-path <path>` | `.nmap_analyzer/chroma` | Persistent ChromaDB path |
| `--embedding-model <model>` | `nomic-embed-text` | Local Ollama embedding model |
| `--ai-timeout <secs>` | `10` | Ollama **connection** timeout. Generation itself has no timeout — the model runs until done. |
| `--max-ai-commands <n>` | `8` | Max AI-generated commands per service |

`--ai-model` is still accepted as a backward-compatible alias for `--model`.

#### Execution options

| Flag | Default | Description |
|------|---------|-------------|
| `--execute` | off | Execute safe enumeration commands (prompts for confirmation) |
| `--dry-run` | off | Build the iterative plan and `case_state.json` without executing commands |
| `--manual-only` | off | Never auto-execute commands; keep actions as analyst-reviewed recommendations |
| `--exec-timeout <secs>` | `60` | Per-command timeout during execution |
| `--max-exec-commands <n>` | `30` | Max commands to auto-execute |
| `--max-steps <n>` | `0` | Hard cap on iterative workflow steps (`0` = no extra cap) |
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
| `--regenerate-report <report_dir>` | — | Rebuild `report.html` from an existing report directory without re-running scans or AI |
| `--screenshot` | off | Capture web screenshots with `gowitness` after analysis |
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
- Port scanning and read-only fingerprinting (`nmap`, `curl`, `whatweb`, `httpx`, `sslscan`)
- Controlled web content discovery with bounded `ffuf`
- Controlled `feroxbuster` only when `ffuf` is unavailable
- SMB/LDAP/SNMP enumeration, SSH audit, DNS queries, service fingerprinting

**What stays as manual suggestions only (never auto-run):**
- Brute force (hydra, medusa, hashcat, etc.)
- Exploitation (sqlmap, metasploit, impacket wmiexec/psexec, etc.)
- `gobuster` and `dirsearch` by default
- Broad, recursive, credentialed, or noisy commands

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

## Regenerate Existing Report

If you already have a report directory and only want to rebuild `report.html` without re-running scans, AI, or execution:

```bash
./analyzer.sh --regenerate-report reports/myproject_20260506_120000
```

This is useful after template or reporting changes.

## Screenshot Capture

Use `--screenshot` to capture web screenshots with `gowitness` after analysis:

```bash
./analyzer.sh scan.xml -C myproject --ai --screenshot
./analyzer.sh scan.xml -C myproject --ai --execute --remote-host kali@10.10.10.5 --screenshot
```

Notes:
- `gowitness` must be installed on the machine that performs the screenshot step
- with `--remote-host`, screenshots run from the remote host

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

The tool uses a local SQLite database (`data/cve_database.db`) built from the NVD REST API and the CISA Known Exploited Vulnerabilities catalog. Only pentest-relevant CVEs are stored — CISA KEV entries plus CVEs with a classifiable exploit type (RCE, auth bypass, privesc, SQLi, SSRF, etc.) and CVSS ≥ 6.0.

### First run — full build (2018–present)

```bash
# Without API key — works but slow (~20–40 min, NVD rate-limits to 5 req/30s)
./analyzer.sh --cve-db-update

# With free NVD API key — ~10× faster (~2–4 min, 50 req/30s)
./analyzer.sh --cve-db-update --nvd-api-key YOUR_KEY_HERE

# Or export the key so every future run picks it up automatically
export NVD_API_KEY=YOUR_KEY_HERE
./analyzer.sh --cve-db-update
```

Get a free NVD API key at: https://nvd.nist.gov/developers/request-an-api-key

The tool auto-detects that no database exists and runs a full import. Output goes to `data/cve_database.db`.

### Subsequent runs — incremental update (fast)

```bash
./analyzer.sh --cve-db-update
```

Once the database exists, the same command switches to incremental mode automatically — it only fetches CVEs published or modified since the last update. Typically completes in under a minute.

### Other database commands

```bash
# Force a full rebuild from scratch (drops and recreates tables)
./analyzer.sh --cve-db-update --cve-rebuild

# Full rebuild covering a specific year range
./analyzer.sh --cve-db-update --cve-rebuild --cve-start-year 2015

# Run the updater directly (bypasses analyzer.sh)
venv/bin/python3 update_cve_db.py --mode full --rebuild
venv/bin/python3 update_cve_db.py --mode incremental
```

## How It Works

```
1. Nmap XML              → Parse hosts, services, versions
2. Role Detection        → Classify hosts (Web, DC, SQL, File Server, etc.)
3. Service Grouping      → Group identical services across hosts
4. CVE Lookup            → Match versions against local NVD database
                            (ranked by CVSS, CISA KEV status, exploit type)
5. Playbook + RAG        → Select static playbooks plus optional markdown/JSON RAG context
6. Network Overview      → (Optional) Summarize the scanned environment
7. Profile Analysis      → (Optional) Apply internal or external pentest reasoning
8. Command Generation    → (Optional) Generate additional safe enumeration commands
9. Command Policy        → Canonical risk classification and normalization
10. Sanity Check         → (Optional) Fail-closed AI review of every command
11. Scope Guard          → Validate target, placeholders, and in-scope execution
12. Iterative Ranking    → Prefer the next smallest evidence-building action
13. Result Review        → Interpret command output and patch case state
14. Evidence to Finding  → Convert only confirmed evidence into findings
15. Report Writing       → Improve wording for evidence-backed findings only
16. Report               → HTML dashboard + text findings + per-command output files
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
│   ├── ai.py                      # Prompt builders + AI command generation + sanity enforcement
│   ├── analysis_loop.py           # Iterative workflow, ranking, result review, and state patching
│   ├── cve.py                     # CVE database lookup (KEV + exploit type aware)
│   ├── executor.py                # Execution orchestration + SSH ControlMaster support
│   ├── models.py                  # Data models (Service, Host, Finding, SanityCheckResult, etc.)
│   ├── parser.py                  # Nmap XML parser
│   ├── pipeline.py                # Main analysis pipeline
│   ├── playbooks.py               # Enumeration playbook matcher
│   ├── providers.py               # AI provider abstraction (Ollama) + stage routing
│   ├── reporting.py               # HTML + text report generation
│   ├── role_detection.py          # Host role classification
│   ├── state.py                   # Persistent iterative case state
│   ├── agents/                    # Explicit multi-agent stage wrappers
│   ├── core/                      # Canonical policy, scope guard, router, schemas, executor helpers
│   ├── knowledge/                 # Markdown playbooks, methodology notes, report language templates
│   ├── rag/                       # ChromaDB + Ollama embedding ingestion and retrieval
│   └── prompts/                   # Structured prompt templates for iterative workflow
├── data/
│   ├── enumeration_playbooks.json # Structured service playbooks used by matching + RAG
│   └── cve_database.db            # Local CVE SQLite database (created after update)
├── logs/                          # Auto-created; run_<timestamp>.log per run
├── reports/                       # Auto-created; one subfolder per run
├── tests/
│   ├── test_assistant.py
│   ├── test_command_sanity_check.py
│   ├── test_iterative_workflow.py
│   ├── test_phase2c_safety_hardening.py
│   ├── test_rag_*.py
│   ├── test_web_discovery_policy.py
│   └── ...
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
