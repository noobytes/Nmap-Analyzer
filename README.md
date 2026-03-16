# Nmap Analyzer

Turn nmap XML into actionable pentest reports — AI attack plans, CVE matching,
risk scoring, and enumeration playbooks in one tool.

## Features

- **Infrastructure role detection** — groups hosts by role (Web Server, Domain Controller, File Server, SQL Server, etc.)
- **120+ enumeration playbooks** — 550+ service-specific commands (Apache, IIS, Tomcat, Samba, WinRM, MSSQL, etc.)
- **CVE cross-referencing** — matches service versions against a local NVD-sourced SQLite database, filters out DoS-only CVEs, ranks by relevance
- **Risk scoring** — prioritizes findings by service criticality, CVE severity, and host count
- **AI-enhanced suggestions** — optional per-service command suggestions via multiple providers
- **AI Attack Plan** — per-service exploitability assessment, attack paths, quick wins, and cross-service correlation analysis
- **Self-contained HTML report** — interactive tabbed dashboard (Dashboard, Enumeration, Attack Plan)
- **Robust** — handles any nmap XML (empty scans, tcpwrapped services, closed ports, malformed data)

## Prerequisites

- **Python 3.10+** (tested on 3.11, 3.12, 3.14)
- **Nmap** — to generate XML scan files (`nmap -oX`)
- **Git** — to clone the repository
- **(Optional) Ollama** — for local AI suggestions without API keys

## Installation

### Step 1: Clone the repository

```bash
git clone https://github.com/noobytes/Nmap-Analyzer.git
cd Nmap-Analyzer
```

### Step 2: Run the setup script

```bash
python3 setup.py
```

This will automatically:
- Create a Python virtual environment (`venv/`)
- Install all dependencies (plotly, defusedxml, httpx, ollama, openai, cai-framework)
- Create required data directories (`data/`, `data/nvd_feeds/`, `reports/`)
- Generate the `analyzer.sh` convenience script
- Verify the package installation
- Check Ollama connectivity (optional)

### Step 3 (Alternative): Manual setup

If you prefer manual installation:

```bash
python3 -m venv venv
source venv/bin/activate        # Linux/macOS
# venv\Scripts\activate         # Windows
pip install -r requirements.txt
mkdir -p data/nvd_feeds reports
```

### Step 4: Build the CVE database (recommended)

```bash
./analyzer.sh --cve-db-update
```

This downloads NVD JSON feeds and builds a local SQLite database at `data/cve_database.db`.
First run does a full import (2002–current year). Subsequent runs do incremental updates.

### Step 5: Configure AI providers (optional)

Copy the example environment file and add your API keys:

```bash
cp .env_example .env
```

Edit `.env` and uncomment the lines for your provider:

```bash
# --- Ollama (Local) ---
# No key needed. Just install Ollama and pull a model:
#   ollama pull qwen2.5-coder:14b
#OLLAMA_HOST=http://127.0.0.1:11434

# --- CAI Framework ---
#CAI_API_KEY=your-cai-api-key-here
#CAI_API_BASE=https://your-cai-endpoint/v1

# --- OpenAI ---
#OPENAI_API_KEY=sk-your-openai-api-key-here

# --- Claude (Anthropic) ---
#ANTHROPIC_API_KEY=sk-ant-your-anthropic-api-key-here
```

The `analyzer.sh` script auto-loads `.env` on startup.

## Usage

### Basic analysis (playbooks only, no AI)

```bash
./analyzer.sh scan.xml -C myproject
```

### With AI suggestions and attack plan

```bash
# Using Ollama (local, default)
./analyzer.sh scan.xml -C myproject --ai

# Using CAI Framework
./analyzer.sh scan.xml -C myproject --ai alias1 --ai-timeout 120

# Using OpenAI
./analyzer.sh scan.xml -C myproject --ai openai

# Using Claude
./analyzer.sh scan.xml -C myproject --ai claude
```

### Update CVE database + analyze in one command

```bash
./analyzer.sh --cve-db-update scan.xml -C acme --ai alias1
```

### Run directly (without analyzer.sh)

```bash
venv/bin/python3 nmap_analyzer.py scan.xml -C myproject --ai alias1
```

### All available options

```bash
./analyzer.sh --help
```

| Flag | Description |
|------|-------------|
| `scan.xml` | Nmap XML file to analyze (required unless `--cve-db-update`) |
| `-C <name>` | Project name — reports saved to `reports/<name>_<timestamp>/` |
| `--ai [provider]` | Enable AI suggestions. Providers: `ollama` (default), `alias1`, `openai`, `claude` |
| `--ai-model <model>` | Override AI model name (default: auto per provider) |
| `--ai-key <key>` | API key (alternative to env vars) |
| `--ai-timeout <secs>` | Timeout per AI request in seconds (default: 60) |
| `--max-ai-commands <n>` | Max AI commands per service (default: 8) |
| `--playbooks <path>` | Custom playbooks JSON file (default: `data/enumeration_playbooks.json`) |
| `--cve-db-update` | Build/update local CVE database from NVD feeds |
| `--cve-rebuild` | Drop and rebuild CVE tables before importing |
| `--cve-offline` | Use only locally cached NVD feed files |
| `--log-level` | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `--debug` | Shortcut for `--log-level DEBUG` |

## Output

Reports are saved to `reports/<project>_<timestamp>/` with two files:

| File | Description |
|------|-------------|
| `findings.txt` | Plain text report with all findings, commands, and attack plan |
| `report.html` | Self-contained interactive HTML report with three tabs |

### HTML Report Tabs

- **Dashboard** — infrastructure overview, role distribution charts, risk heatmap, host inventory, pentest checklists
- **Enumeration** — per-service findings with playbook commands, AI-suggested commands, CVE matches, and risk scores
- **Attack Plan** — (AI only) per-service exploitability assessment, step-by-step attack paths, quick wins, and cross-service correlation analysis

## AI Providers

| Provider | Flag | Model (default) | Notes |
|----------|------|-----------------|-------|
| Ollama | `--ai ollama` | qwen2.5-coder:14b | Free, local, no API key needed |
| CAI Framework | `--ai alias1` | alias1 | Requires CAI endpoint and API key |
| OpenAI | `--ai openai` | gpt-4o | Requires OpenAI API key |
| Claude | `--ai claude` | claude-sonnet-4-20250514 | Requires Anthropic API key |

Override the model with `--ai-model <name>`, e.g.:
```bash
./analyzer.sh scan.xml -C test --ai openai --ai-model gpt-4o-mini
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
```

## CVE Database

The tool uses a local SQLite database (`data/cve_database.db`) sourced from official NVD JSON feeds.

```bash
# Build from scratch (first run — downloads all feeds from 2002)
./analyzer.sh --cve-db-update

# Incremental update (only modified + recent feeds)
./analyzer.sh --cve-db-update

# Force full rebuild
./analyzer.sh --cve-db-update --cve-rebuild

# Offline mode (use cached feeds only)
./analyzer.sh --cve-db-update --cve-offline

# Direct updater script with more options
venv/bin/python3 update_cve_db.py --mode full --rebuild
venv/bin/python3 update_cve_db.py --mode incremental
venv/bin/python3 update_cve_db.py --offline
```

The tool auto-detects whether to run a full or incremental import based on whether the DB exists.

## How It Works

```
1. Nmap XML        → Parse hosts, services, versions
2. Role Detection   → Classify hosts (Web, DC, SQL, File Server, etc.)
3. Service Grouping → Group identical services across hosts
4. CVE Lookup       → Match versions against local NVD database
5. Playbook Match   → Select enumeration commands from 120+ playbooks
6. AI Commands      → (Optional) Generate additional commands per service
7. Risk Scoring     → Prioritize by criticality, CVEs, host count
8. AI Attack Plan   → (Optional) Per-service analysis + cross-service correlations
9. Report           → Generate HTML dashboard + text findings
```

## Project Structure

```
Nmap-Analyzer/
├── analyzer.sh                    # Entry point script (auto-loads .env)
├── nmap_analyzer.py               # CLI interface
├── setup.py                       # Installation script
├── requirements.txt               # Python dependencies
├── .env_example                   # API key template
├── workflow.txt                   # Pipeline flowchart
├── pentest_assistant/             # Core package
│   ├── __init__.py
│   ├── ai.py                     # AI command generation + attack plan
│   ├── cve.py                    # CVE database lookup
│   ├── models.py                 # Data models (Service, Host, Finding, etc.)
│   ├── parser.py                 # Nmap XML parser
│   ├── pipeline.py               # Main analysis pipeline
│   ├── playbooks.py              # Enumeration playbook matcher
│   ├── providers.py              # AI provider abstraction (Ollama, OpenAI, CAI, Claude)
│   ├── reporting.py              # HTML + text report generation
│   └── role_detection.py         # Host role classification
├── data/
│   └── enumeration_playbooks.json # 120+ service playbooks
├── dashboard/
│   └── dashboard.html             # Dashboard template
├── tests/
│   ├── test_assistant.py          # Core functionality tests (27 tests)
│   ├── test_cve_updater.py        # CVE updater tests
│   ├── test_dashboard.py          # Dashboard generation tests
│   └── test_reporting.py          # Report generation tests
└── update_cve_db.py               # NVD feed downloader + importer
```

## Offline Operation

After the initial CVE feed download:
- Scan analysis works fully offline using `data/cve_database.db`
- CVE updates can use cached feeds with `--cve-offline`
- AI features require network access (except Ollama running locally)

## Running Tests

```bash
./venv/bin/python -m pytest tests/ -v
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `ModuleNotFoundError` | Run `python3 setup.py` or `pip install -r requirements.txt` |
| `CVE database not found` | Run `./analyzer.sh --cve-db-update` |
| `Ollama unavailable` | Install from https://ollama.com, then `ollama pull qwen2.5-coder:14b` |
| `No API key for provider` | Add your key to `.env` (see `.env_example`) or use `--ai-key` |
| `AI Attack Plan empty` | Increase timeout: `--ai-timeout 120` |
| `Permission denied: analyzer.sh` | Run `chmod +x analyzer.sh` |
| Reports not generated | Ensure `reports/` directory exists: `mkdir -p reports` |

## License

MIT
