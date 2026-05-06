# Usage Cheat Sheet

This is the short operator guide.

## 1. First-Time Setup

```bash
git clone git@github.com:lzyh00ps/Nmap-Analyzer.git
cd Nmap-Analyzer
python3 setup.py
pip install chromadb
ollama serve
```

In another terminal:

```bash
ollama pull qwen3:30b
ollama pull gemma4:26b
ollama pull nomic-embed-text
./analyzer.sh --cve-db-update
python -m pentest_assistant.rag.ingest --knowledge-dir pentest_assistant/knowledge --reset
```

## 2. Most Common Commands

### Basic, no AI

```bash
./analyzer.sh scan.xml -C client
```

### AI analysis

```bash
./analyzer.sh scan.xml -C client --ai
```

### Internal assessment

```bash
./analyzer.sh scan.xml -C client --ai --preset deep --profile internal
```

### External assessment

```bash
./analyzer.sh scan.xml -C client --ai --preset quick --profile external
```

### Internal + RAG

```bash
./analyzer.sh scan.xml -C client --ai --preset deep --profile internal --rag
```

### Plan only

```bash
./analyzer.sh scan.xml -C client --ai --preset deep --profile internal --workflow iterative --rag --dry-run
```

### Execute approved actions

```bash
./analyzer.sh scan.xml -C client --ai --preset deep --profile internal --workflow iterative --rag --execute --max-steps 5
```

### Remote execution

```bash
./analyzer.sh scan.xml -C client --ai --preset deep --profile internal --workflow iterative --rag --execute --max-steps 5 --remote-host kali@192.168.1.100
```

## 3. What the Main Flags Mean

| Flag | Meaning |
|---|---|
| `--ai` | enable multi-agent AI analysis |
| `--preset quick` | faster balanced mode |
| `--preset deep` | deeper reasoning mode |
| `--profile internal` | internal network reasoning |
| `--profile external` | external attack-surface reasoning |
| `--rag` | use local knowledge retrieval |
| `--rag-rebuild` | rebuild the local vector database first |
| `--dry-run` | no command execution, plan only |
| `--execute` | run approved safe commands |
| `--manual-only` | never auto-execute |
| `--max-steps 5` | stop after 5 iterative steps |
| `--remote-host USER@HOST` | execute from a remote host via SSH |

## 4. Simple Execution Logic

```text
scan.xml
  -> parse
  -> playbooks + CVEs
  -> optional AI
  -> optional RAG
  -> command_policy
  -> command_sanity_check
  -> scope_guard
  -> dry-run or execute
  -> result review
  -> report
```

## 5. Safe Workflow Recommendation

Start with:

```bash
./analyzer.sh scan.xml -C client --ai --preset deep --profile internal --workflow iterative --rag --dry-run
```

If the plan looks good, run:

```bash
./analyzer.sh scan.xml -C client --ai --preset deep --profile internal --workflow iterative --rag --execute --max-steps 5
```

## 6. RAG Setup Only

```bash
pip install chromadb
ollama pull nomic-embed-text
python -m pentest_assistant.rag.ingest --knowledge-dir pentest_assistant/knowledge --reset
```

Use it with:

```bash
./analyzer.sh scan.xml -C client --ai --rag
```

## 7. Web Discovery Behavior

Autonomous order:

1. `ffuf`
2. `feroxbuster` only if `ffuf` is unavailable

Not auto-run by default:

- `gobuster`
- `dirsearch`

Safe `ffuf` example:

```bash
ffuf -u http://TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -ac -mc 200,204,301,302,307,401,403 -t 10 -rate 50 -timeout 10
```

## 8. Useful Extra Commands

### Rebuild report only

```bash
./analyzer.sh --regenerate-report reports/myproject_20260506_120000
```

### Capture screenshots

```bash
./analyzer.sh scan.xml -C client --ai --screenshot
```

### Update CVE DB

```bash
./analyzer.sh --cve-db-update
```

### Use a custom wordlist

```bash
./analyzer.sh scan.xml -C client --ai --wordlist /path/to/wordlist.txt
```
