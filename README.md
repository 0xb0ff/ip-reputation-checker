# IPChecker (AbuseIPDB + VirusTotal)

Small CLI tool to check an IP address reputation using:
- **AbuseIPDB** (API v2)
- **VirusTotal** (API v3)

## Features

- AbuseIPDB reputation score, basic metadata (country, ISP, domain, reports, etc.)
- VirusTotal analysis stats (malicious/suspicious/harmless/undetected/timeout)
- Human-readable output **or** raw JSON output
- API keys via CLI args or environment variables

## Requirements

- Python **3.10+** recommended
- An **AbuseIPDB** API key
- A **VirusTotal** API key

## Install (from source)

```bash
git clone https://github.com/0xb0ff/ip-reputation-checker.git
cd ip-reputation-checker

python -m venv .venv
source .venv/bin/activate

pip install -U pip
pip install -e .
```

## Configure API keys

Export environment variables:

```bash
export ABUSEIPDB_API_KEY="..."
export VIRUSTOTAL_API_KEY="..."
```

> Never commit real API keys into Git.

## Usage

### Same style you use today

Once installed, you can run:

```bash
python -m ipchecker 8.8.8.8
```

### CLI options

```bash
python -m ipchecker 8.8.8.8 --max-age 90 --timeout 10
python -m ipchecker 8.8.8.8 --verbose
python -m ipchecker 8.8.8.8 --json
```

### With explicit keys

```bash
python -m ipchecker 8.8.8.8 --abuseip-api-key "..." --virustotal-api-key "..."
```

## Development

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT (see [LICENSE](LICENSE)).
