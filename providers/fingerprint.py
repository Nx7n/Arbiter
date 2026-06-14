import re
import json
import os
import random
import requests
from typing import List, Tuple, Dict, Any, Optional
import dns.resolver

from .base import BaseProvider
from config import SIGNAL_SCORES, USER_AGENTS, HTTP_TIMEOUT

class GenericFingerprintProvider(BaseProvider):
    """
    Covers all vulnerable services from EdOverflow's fingerprints.json.
    Dynamically builds cname_patterns from the loaded entries.
    """

    def __init__(self):
        self.entries: List[Dict[str, Any]] = []
        self._patterns: List[str] = []
        self._load_fingerprints()

    def _load_fingerprints(self):
        path = os.path.join(
            os.path.dirname(__file__), '..', 'fingerprints', 'fingerprints.json'
        )
        try:
            with open(path) as f:
                data = json.load(f)
                # Keep only entries that are confirmed vulnerable
                self.entries = [
                    e for e in data
                    if e.get('vulnerable') and e.get('status', '').lower() == 'vulnerable'
                ]
        except Exception:
            self.entries = []

        # Build regex patterns from all CNAMEs across all entries
        for entry in self.entries:
            for cname_raw in entry.get('cname', []):
                # Skip raw IP addresses
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', cname_raw):
                    continue
                # Convert glob-ish to regex (simple escape and anchor)
                regex = cname_raw.replace('.', r'\.')
                # Ensure it ends with a word boundary / end-of-string
                if not regex.endswith('$'):
                    regex += '$'
                self._patterns.append(regex)

    @property
    def cname_patterns(self) -> List[str]:
        return self._patterns

    # error_regex is not used directly; checks are per-entry
    error_regex = ""

    def verify_backend(self, domain: str, cname_chain: List[str]) -> Tuple[bool, str]:
        """
        When this provider is matched, we iterate through the entries
        to find which one's CNAME matched, then perform the required
        check (NXDOMAIN, HTTP fingerprint, or status code).
        """
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10

        for entry in self.entries:
            cname_list = entry.get('cname', [])
            if not cname_list:
                continue

            # Find which CNAME in the chain triggered this entry
            matched_cname = None
            for pattern_raw in cname_list:
                # Build same regex as before
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', pattern_raw):
                    continue
                regex = pattern_raw.replace('.', r'\.') + '$'
                for cname in cname_chain:
                    if re.search(regex, cname, re.IGNORECASE):
                        matched_cname = cname
                        break
                if matched_cname:
                    break

            if not matched_cname:
                continue

            service = entry.get('service', 'Unknown')
            nxdomain = entry.get('nxdomain', False)
            fingerprint = entry.get('fingerprint', '')
            http_status = entry.get('http_status')

            # 1. NXDOMAIN check
            if nxdomain:
                if self._is_target_nxdomain(matched_cname, resolver):
                    return True, f"{service}: CNAME target {matched_cname} is NXDOMAIN"

            # 2. HTTP fingerprint check
            if fingerprint and fingerprint.strip().upper() != "NXDOMAIN":
                error_match, proto, status = self._check_http_fingerprint(
                    domain, fingerprint, http_status
                )
                if error_match:
                    return True, f"{service}: error page confirmed ({proto}, HTTP {status})"

            # 3. Some entries have no fingerprint nor nxdomain, but are vulnerable.
            #    We already confirmed CNAME match, so consider it vulnerable.
            if not nxdomain and not fingerprint:
                return True, f"{service}: CNAME matched (no additional checks)"

        # None of the entries' conditions were met (e.g., NXDOMAIN expected but target resolves)
        return False, "Generic fingerprint CNAME matched but backend not confirmed missing"

    def _is_target_nxdomain(self, cname: str, resolver: dns.resolver.Resolver) -> bool:
        """Return True if the given CNAME target does not resolve."""
        try:
            resolver.resolve(cname, 'A')
            return False
        except dns.resolver.NXDOMAIN:
            return True
        except Exception:
            return False

    def _check_http_fingerprint(self, domain: str, fingerprint: str,
                                required_status: Optional[int] = None) -> Tuple[bool, Optional[str], Optional[int]]:
        """HTTP check with optional required HTTP status code."""
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        for protocol in ("https", "http"):
            url = f"{protocol}://{domain}"
            try:
                resp = requests.get(url, timeout=HTTP_TIMEOUT, allow_redirects=True,
                                    verify=False, headers=headers)
                if required_status is not None and resp.status_code != required_status:
                    continue
                haystack = f"{resp.status_code} {resp.text} {str(resp.headers)}"
                if re.search(fingerprint, haystack, re.IGNORECASE):
                    return True, protocol, resp.status_code
            except Exception:
                continue
        return False, None, None