# TrueOrigin

Origin IP discovery and proxy analysis tool for authorized security testing.

Identifies infrastructure behind CDNs, reverse proxies, and DDoS protection services using legitimate, non-intrusive techniques.

## Requirements

- Python 3.8+
- No external dependencies

## Usage

```bash
python trueorigin.py example.com
python trueorigin.py example.com -e          # extended port scan
python trueorigin.py example.com -v          # verbose output
python trueorigin.py example.com --json      # JSON output
```

### Options

| Flag | Description |
|------|-------------|
| `-e, --extended` | Extended port scan |
| `-t, --timeout` | Connection timeout (default: 5s) |
| `-v, --verbose` | Verbose output |
| `--skip-inference` | Skip advanced inference |
| `--json` | JSON output |
| `--no-color` | Disable colors |

## How It Works

1. Target validation and DNS resolution
2. Port discovery (TCP connect scan)
3. Proxy/CDN detection per port
4. Cross-port correlation analysis
5. DNS-based origin inference
6. RDAP enrichment
7. Confidence scoring

## Output

Results are ranked by confidence:

- **HIGH** - Strong evidence convergence
- **MEDIUM** - Plausible, needs verification
- **LOW** - Weak indicator

`[EDGE/CDN]` marks IPs belonging to known CDN providers.

## Project Structure

```
trueorigin/
├── trueorigin.py        # main entry point
├── src/
│   ├── validator.py     # target validation
│   ├── scanner.py       # port discovery
│   ├── fingerprint.py   # TLS/HTTP fingerprinting
│   ├── proxy_detector.py
│   ├── dns_analysis.py
│   ├── correlator.py    # cross-port analysis
│   ├── inference.py     # advanced techniques
│   ├── scoring.py       # confidence scoring
│   ├── output.py        # result formatting
│   └── utils.py         # shared utilities
└── requirements.txt
```

## Limitations

- Cannot bypass properly configured CDNs
- DNS discovery depends on misconfigurations
- Shared hosting may reduce accuracy

## Legal

**Authorized use only.** This tool is intended for:

- Security audits on systems you own
- Penetration tests with written authorization
- Educational and research purposes

The authors assume no liability for misuse.

## License

MIT
