"""
Subdomain Takeover Validator - Confidence-based validation engine.
Usage:
    python validator.py -i input.txt -o results.json
"""

import argparse
import logging
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Optional
import dns.resolver
import requests
from config import *
from core.dns import resolve_chain, check_dangling_ns, is_domain_expired
from core.http import check_http_error, analyse_headers
from core.tls import get_tls_signals
from core.scoring import compute_confidence, Verdict
from providers.registry import get_provider_for_cname
from input.subzy import parse_subzy_output
from input.subjack import parse_subjack_output
from input.generic import parse_generic_list
from output.csv import write_csv
from output.json import write_json


# ==============================
# Terminal colours & banner
# ==============================
USE_COLOR = sys.stdout.isatty()

COLORS = {
    "VULN": "\033[31m",     # Red for confirmed/likely
    "SUSPICIOUS": "\033[33m",  # Yellow
    "SAFE": "\033[32m",     # Green
    "INFO": "\033[36m",     # Cyan
    "BOLD": "\033[1m",
    "RESET": "\033[0m",
}

def colorize(text: str, color: str) -> str:
    if USE_COLOR:
        return f"{COLORS.get(color, '')}{text}{COLORS['RESET']}"
    return text

BANNER = r"""


   _____         ___.    .__   __                  
  /  _  \ _______\_ |__  |__|_/  |_   ____ _______ 
 /  /_\  \\_  __ \| __ \ |  |\   __\_/ __ \\_  __ \
/    |    \|  | \/| \_\ \|  | |  |  \  ___/ |  | \/
\____|__  /|__|   |___  /|__| |__|   \___  >|__|   
        \/            \/                 \/        

                                                          
                    SUBTAKEOVER VALIDATOR BY nx7n
"""

requests.packages.urllib3.disable_warnings()

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

def validate_domain(domain: str, resolver: dns.resolver.Resolver) -> dict:
    """Run all checks and return a result dictionary."""
    result = {
        "domain": domain,
        "cname_chain": [],
        "signals": [],
        "confidence": 0,
        "verdict": Verdict.FALSE_POSITIVE.name,
        "details": {}
    }

    # DNS chain resolution
    chain = resolve_chain(domain, resolver)
    result["cname_chain"] = [str(c) for c in chain]

    full_chain = [domain] + chain

    # Check for dangling NS
    if check_dangling_ns(domain, resolver):
        result["signals"].append({
            "name": "dangling_ns",
            "score": SIGNAL_SCORES["dangling_ns"],
            "description": "Dangling NS record (zone no longer exists)"
        })

    # Inspect hop in CNAME chain
    provider = None
    for i, cname in enumerate(full_chain):
        # Identify provider from CNAME
        p = get_provider_for_cname(cname)
        if p:
            provider = p
            result["signals"].append({
                "name": "vulnerable_provider_detected",
                "score": SIGNAL_SCORES["vulnerable_provider_detected"],
                "description": f"CNAME hop {i}: {cname} -> {provider.__class__.__name__}"
            })
            break  # first vulnerable provider wins

        # expired domain check
        if i > 0 and is_domain_expired(cname):
            result["signals"].append({
                "name": "expired_domain_in_chain",
                "score": SIGNAL_SCORES["expired_domain_in_chain"],
                "description": f"CNAME target {cname} appears expired/unregistered"
            })

    # Provider‑specific backend verification + HTTP checks
    if provider:
        
        missing, msg = provider.verify_backend(domain, chain)
        if missing:
            result["signals"].append({
                "name": "service_api_confirms_missing",
                "score": SIGNAL_SCORES["service_api_confirms_missing"],
                "description": msg
            })

        # HTTP error fingerprint
        error_match, protocol, status = check_http_error(domain, provider.error_regex)
        if error_match:
            result["signals"].append({
                "name": "error_page_fingerprint",
                "score": SIGNAL_SCORES["error_page_fingerprint"],
                "description": f"Error page detected ({protocol}, HTTP {status})"
            })

        # Header analysis 
        headers, has_cdn = analyse_headers(domain)            # Vercel behind cdn
        if headers.get("x-vercel-id"):
            result["signals"].append({
                "name": "header_reveals_provider",
                "score": 10,
                "description": "Header 'x-vercel-id' found despite non‑Vercel CNAME"
            })
        elif headers.get("server") and "netlify" in headers["server"].lower():
            result["signals"].append({
                "name": "header_reveals_provider",
                "score": 10,
                "description": "Server header indicates Netlify"
            })
        # *Add more headers in future

    # TLS fingerprinting
    tls_signals = get_tls_signals(domain, chain)
    result["signals"].extend(tls_signals)

    result["confidence"] = compute_confidence(result["signals"])
    if result["confidence"] >= CONFIDENCE_CONFIRMED:
        result["verdict"] = Verdict.CONFIRMED.name
    elif result["confidence"] >= CONFIDENCE_LIKELY:
        result["verdict"] = Verdict.LIKELY.name
    elif result["confidence"] >= CONFIDENCE_SUSPICIOUS:
        result["verdict"] = Verdict.SUSPICIOUS.name
    else:
        result["verdict"] = Verdict.FALSE_POSITIVE.name

    result["details"] = {
        "signals": result["signals"],
        "chain": result["cname_chain"]
    }
    return result

def main():
    parser = argparse.ArgumentParser(description="Confidence-based subdomain takeover validator")
    parser.add_argument("-i", "--input", required=True, help="Input file (Subzy, Subjack, or domain list)")
    parser.add_argument("-o", "--output", help="Output file (.json or .csv)")
    parser.add_argument("-t", "--type", choices=["subzy", "subjack", "generic"], default="generic",
                        help="Input file format (default: generic domain list)")
    parser.add_argument("-c", "--concurrency", type=int, default=5, help="Number of threads")
    parser.add_argument("--timeout", type=int, default=HTTP_TIMEOUT, help="HTTP request timeout")
    parser.add_argument("--no-banner", action="store_true" ,help="Don't Display Banner")
    args = parser.parse_args()

    if not args.no_banner:
        print(colorize(BANNER, "BOLD"))

    if args.type == "subzy":
        targets = parse_subzy_output(args.input)
    elif args.type == "subjack":
        targets = parse_subjack_output(args.input)
    else:
        targets = [(line.strip(), "") for line in open(args.input) if line.strip()]

    logger.info(f"Loaded {len(targets)} targets")

    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_LIFETIME

    results = []
    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures = {executor.submit(validate_domain, domain, resolver): domain
                   for domain, _ in targets}
        # Inside the ThreadPoolExecutor loop:
        for future in as_completed(futures):
            domain = futures[future]
            try:
                res = future.result()
                results.append(res)
                verdict = res["verdict"]
                confidence = res["confidence"]

                # Choose colour based on verdict
                if verdict in ("CONFIRMED", "LIKELY"):
                    colour = "VULN"
                elif verdict == "SUSPICIOUS":
                    colour = "SUSPICIOUS"
                else:
                    colour = "SAFE"

                msg = f"{verdict:>15} | {confidence:>3}% | {domain}"
                print(colorize(msg, colour))
            except Exception as e:
                print(colorize(f"  ERROR       |   0% | {domain} - {e}", "VULN"))

    if args.output:
        if args.output.endswith(".json"):
            write_json(results, args.output)
        elif args.output.endswith(".csv"):
            write_csv(results, args.output)
        else:
            write_json(results, args.output + ".json")
        logger.info(f"Results saved to {args.output}")

    from collections import Counter

    verdict_counts = Counter(r["verdict"] for r in results)
    print("\n" + "=" * 60)
    print(colorize("SUMMARY", "INFO"))
    print("=" * 60)
    
    for v in ("CONFIRMED", "LIKELY", "SUSPICIOUS", "FALSE_POSITIVE"):
        count = verdict_counts.get(v, 0)
        if count == 0:
            continue
        colour = "VULN" if v in ("CONFIRMED", "LIKELY") else ("SUSPICIOUS" if v == "SUSPICIOUS" else "SAFE")
        print(colorize(f"  {v}: {count}", colour))

    confirmed = [r for r in results if r["verdict"] == "CONFIRMED"]
    if confirmed:
        print("\n" + colorize("CONFIRMED VULNERABLE DOMAINS", "VULN"))
        for r in confirmed:
            print(colorize(f"  • {r['domain']} (confidence: {r['confidence']}%)", "VULN"))

if __name__ == "__main__":
    main()