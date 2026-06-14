import requests
from .base import BaseProvider
from typing import List, Tuple

class NetlifyProvider(BaseProvider):
    cname_patterns = [r'\.netlify\.com$']
    error_regex = r'Not Found'

    def verify_backend(self, domain: str, cname_chain: List[str]) -> Tuple[bool, str]:
        """
        Netlify sites return a distinctive 404 with 'x-nf-request-id' header.
        """
        try:
            r = requests.head(f"https://{domain}", timeout=5, allow_redirects=True,
                              headers={"User-Agent": "subtakeover-validator"})
            if r.status_code == 404 and "x-nf-request-id" in r.headers:
                return True, "Netlify site missing (404 + x-nf-request-id header)"
 
            r2 = requests.get(f"https://{domain}", timeout=5, allow_redirects=True)
            if r2.status_code == 404 and ("netlify" in r2.text.lower() or "x-nf-request-id" in r2.headers):
                return True, "Netlify site missing (404 with Netlify markers)"
        except requests.RequestException:
            pass
        return False, "Netlify backend check inconclusive"