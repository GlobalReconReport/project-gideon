# Project Gideon — Pentest Lab Orchestrator

Automated penetration testing pipeline that chains **Subfinder → Nmap → Nuclei → Metasploit → Burp Pro / ZAP → Gowitness** and writes a self-contained **HTML + JSON report**.

---

## Features

| Module | Tool | Purpose |
|---|---|---|
| Recon | Subfinder | Subdomain enumeration (domain targets only) |
| Scan | Nmap | Port, service, and OS detection (parallel across subdomains) |
| Vuln scan | Nuclei | Template-based CVE / misconfiguration detection |
| Exploitation | Metasploit | Auto-run auxiliary scanner modules per discovered service |
| Web scan | Burp Pro / ZAP | Spider + active web application scan |
| Screenshots | Gowitness | Screenshots of discovered HTTP/S services |
| Reporting | Built-in | Sorted HTML report + structured JSON output |

---

## Requirements

```bash
pip install requests urllib3 pymetasploit3 python-nmap
apt install subfinder nmap nuclei gowitness
```

Burp Pro and ZAP are optional — the pipeline falls back gracefully if neither is reachable.

---

## Usage

```bash
python pentest_lab.py -t <target>
```

### Examples

```bash
# Scan a single IP
python pentest_lab.py -t 10.0.0.1

# Scan a domain (runs Subfinder first, then Nmap across all subdomains in parallel)
python pentest_lab.py -t example.com

# Skip modules you don't need
python pentest_lab.py -t 10.0.0.1 --skip-msf --skip-burp

# Use specific Nuclei templates
python pentest_lab.py -t 10.0.0.1 --nuclei-templates cves vulnerabilities

# Dry run — scans only, no report written
python pentest_lab.py -t 10.0.0.1 --dry-run

# Custom output directory and Nmap flags
python pentest_lab.py -t 10.0.0.1 --output-dir ~/engagements --nmap-flags "-sV -T4"
```

### All flags

| Flag | Default | Description |
|---|---|---|
| `-t / --target` | required | IP, hostname, or CIDR range |
| `--skip-recon` | off | Skip Subfinder |
| `--skip-nmap` | off | Skip Nmap |
| `--skip-nuclei` | off | Skip Nuclei |
| `--skip-msf` | off | Skip Metasploit |
| `--skip-burp` | off | Skip Burp/ZAP |
| `--skip-shots` | off | Skip Gowitness screenshots |
| `--nuclei-templates` | nuclei defaults | Template paths/tags |
| `--nmap-flags` | `-sV -sC -O --open -T4` | Nmap arguments |
| `--scan-workers` | `5` | Parallel Nmap workers for subdomain scanning |
| `--output-dir` | `./reports` | Report output directory |
| `--custom-scripts` | none | Paths to `.sh` / `.py` scripts (see below) |
| `--dry-run` | off | Run scans but skip writing reports |

---

## Environment variables

Credentials are never hardcoded. Set these before running:

```bash
export MSF_PASS=yourpassword        # msfrpcd password
export MSF_USER=msf                 # msfrpcd username (default: msf)
export MSF_HOST=127.0.0.1           # msfrpcd host
export MSF_PORT=55553               # msfrpcd port
export MSF_SSL=false                # msfrpcd SSL

export BURP_API_KEY=yourkey         # Burp Pro REST API key
export BURP_URL=http://127.0.0.1:1337

export ZAP_API_KEY=yourkey          # ZAP API key
export ZAP_URL=http://127.0.0.1:8080
```

---

## Custom scripts

Pass any `.sh` or `.py` scripts with `--custom-scripts`. Each script receives the target as its first argument and must write findings as a JSON array to stdout:

```json
[
  {"name": "Finding name", "desc": "Details", "severity": "high"}
]
```

Valid severity values: `critical`, `high`, `med`, `low`, `info`, `unclassified`.

---

## Reports

Reports are written to `./reports/` (or `--output-dir`) on each run:

```
reports/
  gideon_10.0.0.1_20260316_120000.json
  gideon_10.0.0.1_20260316_120000.html
```

The HTML report is self-contained — open it in any browser. Findings are sorted by severity.

---

## Running tests

```bash
pip install pytest
python -m pytest test_pentest_lab.py -v
```

47 tests covering `_is_domain`, `ReportBuilder`, `_render_html`, severity maps, `run_cmd`, and `run_custom_scripts`.

---

## Starting Metasploit RPC

```bash
msfrpcd -U msf -P yourpassword -p 55553 -n -f
```

## Starting ZAP (headless)

```bash
zaproxy -daemon -port 8080 -config api.key=yourkey
```
