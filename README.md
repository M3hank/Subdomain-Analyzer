# Subdomain Analyzer

Subdomain Analyzer is a highly concurrent, intelligent scoring system designed to evaluate subdomains and prioritize reconnaissance efforts for security researchers and bug bounty hunters. 

By analyzing hostnames, technologies, historical URLs, and certificate age, this tool assigns a quantifiable **risk score** (INFO to CRITICAL) to help you focus on the most lucrative targets first.

## Features

- **Keyword Analysis**: Detects over 100 high/medium criticality keywords (e.g., `admin`, `api`, `dev`, `stage`) in the subdomain name.
- **Historical URL Profiling**: Integrates with `gau` (GetAllUrls) to fetch known paths and analyzes them for exposed sensitive endpoints (`/.git`, `/api`, `/wp-admin`).
- **Technology Fingerprinting**: Identifies the tech stack using `Wappalyzer` and assigns risk points for outdated or complex technologies.
- **Subdomain Age Tracking**: queries `crt.sh` and the `Wayback Machine` to determine the earliest known use of the subdomain. Older, forgotten subdomains score higher.
- **Multi-threaded**: Fast, concurrent processing (default: 10 threads).
- **Flexible Reporting**: Output results to `JSON`, `CSV`, or a human-readable `TXT` format.

## Requirements

Ensure you have Python 3 installed. Install the required Python packages:

```bash
pip install -r requirements.txt
```

### External Dependencies
- Ensure [gau (GetAllUrls)](https://github.com/lc/gau) is installed and available in your system's `PATH` for historical URL fetching to work.

## Usage

```bash
python subdomain.py -i <input_file> -o <output_file> [options]
```

### Arguments

| Argument | Description | Default |
|---|---|---|
| `-i`, `--input` | **(Required)** Input file with subdomains (one per line) | - |
| `-o`, `--output` | **(Required)** Output report file path | - |
| `-f`, `--format` | Output report format (`txt`, `json`, `csv`) | `txt` |
| `-t`, `--threads` | Number of concurrent threads | `10` |
| `--timeout` | HTTP request timeout in seconds | `10` |
| `--no-gau` | Skip historical URL fetching via `gau` | `False` |
| `--no-wappalyzer` | Skip Wappalyzer technology detection | `False` |
| `-v`, `--verbose` | Enable verbose console output | `False` |

## Example

Analyze a list of subdomains in `subs.txt`, output to a beautifully formatted JSON report with 20 threads:

```bash
python subdomain.py -i subs.txt -o report.json -f json --threads 20 -v
```

## How It Scores

The system determines risk levels based on total accumulated points:
- **CRITICAL** (50+ points): High probability of serious findings.
- **HIGH** (30-49 points): Interesting targets, likely containing staging environments or sensitive tech.
- **MEDIUM** (15-29 points): Worth checking, standard points of entry.
- **LOW** (5-14 points): Standard production or static applications.
- **INFO** (0-4 points): Insignificant or dead targets.
