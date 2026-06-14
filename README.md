# Arbiter

> Confidence‑based subdomain takeover validator with DNS chain resolution,
> provider‑specific backend verification, and 100+ service fingerprints.

A confidence‑based verifier for subdomain takeover findings and reduces false positives.


## Features

- **DNS CNAME chain resolution** – inspects every hop, not just the first CNAME
- **Multi‑signal confidence scoring** – weighs provider match, error page,
  NXDOMAIN, TLS mismatch, backend API verification
- **Dedicated provider modules** (GitHub Pages, Vercel, Netlify, Heroku, S3)
  with direct backend existence checks
- **Generic fingerprint provider** – loads the full can‑i‑take‑over‑xyz
  fingerprints.json for 100+ services
- **CDN masking detection** via response headers (x‑vercel‑id, server: Netlify, etc.)
- **TLS fingerprinting** – certificate mismatch, default certs, missing SANs
- **Subzy / Subjack / plain** domain list input support
- **JSON & CSV output** with full confidence breakdown


## Installation
```bash
git clone <your-repo-url>
cd subtakeover-validator
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
Requirements: dnspython, requests, python-whois


## Quick Start

### Validate a Subzy output file
```bash
python validator.py -i subzy_results.txt -t subzy -o findings.json
```

### Validate a plain domain list
```bash
python validator.py -i live_subdomains.txt -t generic -o results.csv
```

### Validate a Subjack JSON
```bash
python validator.py -i subjack.json -t subjack -o verified.json
```

## Usage
```bash
python validator.py -i INPUT -t {subzy,subjack,generic} [options]

Options:
  -i, --input         Input file
  -o, --output        Output file (.json or .csv)
  -t, --type          Input type: subzy, subjack, or generic (default: generic)
  -c, --concurrency   Number of threads (default: 5)
  --timeout           HTTP timeout in seconds (default: 10)
  --no-color          Disable coloured terminal output
  --no-banner         Hide ASCII art banner
```

## Output

Results are printed live to the terminal in colour, and optionally saved.
```
Confidence levels:
  • 70–100%  →  CONFIRMED (red)
  • 40–69%   →  LIKELY (yellow)
  • 20–39%   →  SUSPICIOUS (yellow)
  • 0–19%    →  FALSE_POSITIVE (green)
```
```json
Each entry contains:
[
  {
    "domain": "does-not-exist-12345.herokuapp.com",
    "cname_chain": ["va01.ingress.herokuapp.com"],
    "signals": [
      {
        "name": "vulnerable_provider_detected",
        "score": 40,
        "description": "CNAME hop 0: ... -> HerokuProvider"
      },
      {
        "name": "service_api_confirms_missing",
        "score": 50,
        "description": "Heroku app missing (404 + 'No such app')"
      },
      {
        "name": "error_page_fingerprint",
        "score": 30,
        "description": "Error page detected (https, HTTP 404)"
      }
    ],
    "confidence": 100,
    "verdict": "CONFIRMED"
  }
]
```

## Directory Structure
```
subtakeover-validator/
├── validator.py            # Main engine
├── config.py               # Scoring thresholds & settings
├── requirements.txt
├── core/
│   ├── dns.py              # CNAME chain, NS checks, expiry
│   ├── http.py             # HTTP error page & header analysis
│   ├── tls.py              # TLS certificate fingerprinting
│   └── scoring.py          # Confidence calculation
├── providers/
│   ├── base.py             # Abstract base class
│   ├── github.py
│   ├── vercel.py
│   ├── netlify.py
│   ├── heroku.py
│   ├── s3.py
│   ├── fingerprint.py      # Loads fingerprints.json
│   └── registry.py         # Provider auto‑discovery
├── fingerprints/
│   └── fingerprints.json   # EdOverflow's database
├── input/                  # Parsers (subzy, subjack, generic)
└── output/                 # JSON & CSV writers

```
## Supported Services

### Dedicated providers (with direct backend checks):
  - GitHub Pages
  - Vercel
  - Netlify
  - Heroku
  - Amazon S3

### Generic fingerprints (from can‑i‑take‑over‑xyz):

  AWS/Elastic Beanstalk, Microsoft Azure, Shopify, Wordpress, Squarespace, Wix, Webflow, Tumblr, Zendesk, Freshdesk, Help Scout, Intercom, Readthedocs, Surge.sh, Strikingly,
  UptimeRobot, LaunchRock, Ngrok, Pantheon, Pingdom, SmartJobBoard, UserVoice, Campaign Monitor, Canny, Helprace, Gemfury, Ghost, Agile CRM, JetBrains, Airee.ru,and many more (100+).

The fingerprints/fingerprints.json file is loaded at runtime – you can update it independently to get the latest definitions.


## Credits

- Original verifier concept by nx7n
- Confidence scoring & provider architecture built by nx7n
- can‑i‑take‑over‑xyz fingerprint database by EdOverflow and community

## Future Work

- **More provider modules** – add dedicated backend checks for Shopify,
  Wix, Webflow, Readthedocs, Pantheon, and other frequently abused services.

- **Historical DNS integration** – query SecurityTrails, VirusTotal, or
  DNSDB to see if a subdomain previously pointed to a vulnerable provider,
  strengthening the confidence signal.

- **API‑driven backend verification** – where a provider offers a public
  API (GitHub, Vercel, Netlify), use it to confirm resource existence
  without relying solely on HTTP error pages.

- **Improved TLS fingerprinting** – parse SANs, detect expired/self‑signed
  certificates, and match default provider certs (e.g., `*.herokudns.com`).

- **Expanded header analysis** – detect more CDN‑masked providers by
  inspecting `x‑powered‑by`, `cf‑ray`, `x‑amz‑cf‑id`, and similar headers.

- **Report generation** – produce a single PDF/HTML report summarising
  all confirmed and likely takeovers with evidence blocks.

- **Live subdomain discovery** – integrate with tools like `subfinder`,
  `amass`, or `chaos` to feed directly into the validator.

## License

MIT – see the LICENSE file for details.