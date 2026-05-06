# Nmap Analyzer

Local-first, safety-focused, AI-assisted Nmap analysis for authorized penetration testing.

This project takes Nmap XML, matches services to playbooks and CVEs, optionally adds local Ollama-based multi-agent analysis, optionally uses local RAG knowledge, and can run only tightly controlled enumeration commands.

If you want the shortest operator guide, read [USAGE.md](USAGE.md).

## What It Does

- parses one or more Nmap XML files
- groups hosts and services
- matches local playbooks and CVEs
- uses local AI agents for analysis and planning
- uses local RAG for methodology, playbooks, and report language
- generates HTML and text reports
- can optionally execute only approved low-risk enumeration commands

## Safety First

This tool is for authorized pentesting only.

It does **not** automate:

- exploitation
- brute force
- password spraying
- destructive actions
- denial-of-service activity

Every command must pass:

1. `command_policy`
2. `command_sanity_check`
3. `scope_guard`

Only approved, in-scope, safely parsed, low-risk commands can auto-execute.

Controlled web content discovery is the only medium-risk exception:

- `ffuf` can auto-execute only with strict safety limits
- `feroxbuster` is fallback only if `ffuf` is unavailable
- `gobuster` and `dirsearch` stay manual-only by default

## Simple Workflow

```text
            +----------------------+
            |   Nmap XML Input     |
            +----------+-----------+
                       |
                       v
            +----------------------+
            |  Parse Hosts/Ports   |
            +----------+-----------+
                       |
                       v
            +----------------------+
            | Local Playbooks/CVEs |
            +----------+-----------+
                       |
                       v
        +----------------------------------+
        | Optional AI + Optional Local RAG |
        +----------------+-----------------+
                         |
                         v
        +----------------------------------+
        | network_overview                 |
        | profile_analysis                 |
        | command_generation               |
        +----------------+-----------------+
                         |
                         v
        +----------------------------------+
        | command_policy                   |
        | command_sanity_check             |
        | scope_guard                      |
        +----------------+-----------------+
                         |
          +--------------+--------------+
          |                             |
          v                             v
 +----------------------+      +----------------------+
 | manual recommendations|      | approved safe actions|
 +----------------------+      +-----------+----------+
                                            |
                               +------------+-------------+
                               | --dry-run                |
                               | plan only, no execution  |
                               +------------+-------------+
                                            |
                               +------------+-------------+
                               | --execute                |
                               | run approved commands    |
                               +------------+-------------+
                                            |
                                            v
                               +--------------------------+
                               | result_review            |
                               | evidence_to_finding      |
                               | report_writing           |
                               +------------+-------------+
                                            |
                                            v
                               +--------------------------+
                               | HTML + Text + Case State |
                               +--------------------------+
```

## Main Components

| Component | Purpose |
|---|---|
| `network_overview` | Summarizes the scanned environment |
| `profile_analysis` | Reasons differently for internal vs external testing |
| `command_generation` | Suggests safe enumeration commands |
| `command_policy` | Canonical risk classification and normalization |
| `command_sanity_check` | AI safety review for generated commands |
| `scope_guard` | Blocks out-of-scope or malformed target usage |
| `iterative_ranking` | Picks the next best low-risk evidence-building action |
| `result_review` | Interprets command output |
| `evidence_to_finding` | Converts confirmed evidence into findings |
| `report_writing` | Improves language only; cannot invent findings |
| `rag/` | Local embeddings, ChromaDB, retrieval, structured playbook intelligence |

## Quick Start

### 1. Clone

```bash
git clone git@github.com:lzyh00ps/Nmap-Analyzer.git
cd Nmap-Analyzer
```

### 2. Install

```bash
python3 setup.py
```

### 3. Optional: Build CVE Database

```bash
./analyzer.sh --cve-db-update
```

If you have an NVD API key:

```bash
export NVD_API_KEY=YOUR_KEY_HERE
./analyzer.sh --cve-db-update
```

### 4. Optional: Enable AI

Install Ollama and start it:

```bash
ollama serve
```

Then pull the models:

```bash
ollama pull qwen3:30b
ollama pull gemma4:26b
ollama pull nomic-embed-text
```

### 5. Optional: Build Local RAG Database

```bash
pip install chromadb
python -m pentest_assistant.rag.ingest --knowledge-dir pentest_assistant/knowledge --reset
```

## Easiest Commands

### Basic analysis

```bash
./analyzer.sh scan.xml -C client
```

### AI analysis

```bash
./analyzer.sh scan.xml -C client --ai
```

### Internal testing

```bash
./analyzer.sh scan.xml -C client --ai --preset deep --profile internal
```

### External testing

```bash
./analyzer.sh scan.xml -C client --ai --preset quick --profile external
```

### Internal with RAG

```bash
./analyzer.sh scan.xml -C client --ai --preset deep --profile internal --rag
```

### Plan only, no execution

```bash
./analyzer.sh scan.xml -C client --ai --preset deep --profile internal --workflow iterative --rag --dry-run
```

### Execute approved actions

```bash
./analyzer.sh scan.xml -C client --ai --preset deep --profile internal --workflow iterative --rag --execute --max-steps 5
```

### Remote execution from a Kali box

```bash
./analyzer.sh scan.xml -C client --ai --preset deep --profile internal --workflow iterative --rag --execute --max-steps 5 --remote-host kali@192.168.1.100
```

## What `--dry-run` Means

`--dry-run` does **not** execute commands.

It still:

- parses the scan
- runs playbook matching
- runs AI agents if enabled
- runs RAG if enabled
- ranks actions
- writes `case_state.json`
- generates report output

It does **not**:

- run `nmap`, `curl`, `ffuf`, `sslscan`, or similar commands
- connect to targets for validation

Think of it as:

- `--dry-run` = show me the plan
- `--execute` = run the approved plan

## RAG in Plain Language

RAG lets the agents use local reference material:

- service playbooks
- pentest methodology notes
- report wording templates
- structured JSON playbook intelligence

RAG is **supporting context only**.

It is not proof.
Findings still require confirmed evidence from:

- Nmap results
- command output

## Presets

| Preset | Good For |
|---|---|
| `quick` | faster external or light review |
| `deep` | fuller internal or iterative analysis |

Stage routing:

| Stage | Default | `quick` | `deep` |
|---|---|---|---|
| `network_overview` | `qwen3:30b` | `gemma4:26b` | `gemma4:26b` |
| `profile_analysis` | `qwen3:30b` | `qwen3:30b` | `qwen3:30b` |
| `command_generation` | `qwen3:30b` | `qwen3:30b` | `qwen3:30b` |
| `command_sanity_check` | `qwen3:30b` | `qwen3:30b` | `qwen3:30b` |
| `iterative_ranking` | `qwen3:30b` | `qwen3:30b` | `qwen3:30b` |
| `result_review` | `qwen3:30b` | `gemma4:26b` | `qwen3:30b` |
| `evidence_to_finding` | `qwen3:30b` | `qwen3:30b` | `qwen3:30b` |
| `report_writing` | `qwen3:30b` | `gemma4:26b` | `gemma4:26b` |

## Output Files

Each run writes to:

```text
reports/<project>_<timestamp>/
```

Common files:

- `report.html`
- `findings.txt`
- `ai_report.txt`
- `live_findings.txt` when execution is used
- `case_state.json` for iterative workflow
- `enumeration/` command outputs

## Web Content Discovery Strategy

Autonomous web discovery is intentionally limited.

Preferred order:

1. `ffuf`
2. `feroxbuster` only if `ffuf` is unavailable

Not auto-used by default:

- `gobuster`
- `dirsearch`

Safe bounded `ffuf` example:

```bash
ffuf -u http://TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -ac -mc 200,204,301,302,307,401,403 -t 10 -rate 50 -timeout 10
```

## Common Useful Flags

| Flag | Meaning |
|---|---|
| `--ai` | enable AI agents |
| `--preset quick|deep` | choose model routing |
| `--profile internal|external` | choose reasoning style |
| `--rag` | enable local retrieval |
| `--rag-rebuild` | rebuild vector DB before analysis |
| `--execute` | run approved commands |
| `--dry-run` | plan only |
| `--manual-only` | never auto-execute |
| `--max-steps 5` | stop iterative workflow after 5 steps |
| `--remote-host USER@HOST` | execute commands remotely over SSH |
| `--wordlist PATH` | override default web content discovery wordlist |
| `--regenerate-report REPORT_DIR` | rebuild HTML report only |
| `--screenshot` | capture web screenshots with `gowitness` |

## Recommended Nmap Commands

```bash
# Internal
nmap -sV -sC -T4 --open -oX scan.xml TARGET_RANGE

# External
nmap -sV -sC -p- -T3 --open -oX scan.xml TARGET_RANGE

# UDP essentials
nmap -sU -sV --top-ports 20 --open -oX udp_scan.xml TARGET_RANGE
```

## Troubleshooting

| Problem | What To Do |
|---|---|
| `chromadb` missing | `pip install chromadb` |
| Ollama unavailable | run `ollama serve` |
| embedding model missing | `ollama pull nomic-embed-text` |
| qwen model missing | `ollama pull qwen3:30b` |
| gemma model missing | `ollama pull gemma4:26b` |
| CVE database missing | run `./analyzer.sh --cve-db-update` |
| remote execution fails | verify SSH access and remote tools |

## More Detail

For a shorter operator cheat sheet, use [USAGE.md](USAGE.md).

## License

MIT
