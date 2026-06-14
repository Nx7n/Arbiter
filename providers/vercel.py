import requests
from .base import BaseProvider
from typing import List, Tuple

class VercelProvider(BaseProvider):
    cname_patterns = [r'\.vercel\.app$', r'\.vercel-dns\.com$']
    error_regex = r'The deployment could not be found|DEPLOYMENT_NOT_FOUND'

    def verify_backend(self, domain: str, cname_chain: List[str]) -> Tuple[bool, str]:
        """
        Vercel indicates a missing deployment with HTTP 404 and specific body.
        Even behind a CDN, headers like x-vercel-id may leak.
        """
        try:
            r = requests.get(f"https://{domain}", timeout=5, allow_redirects=False,
                             headers={"User-Agent": "subtakeover-validator"})

            if r.status_code == 404:
                body = r.text.lower()
                if "deployment_not_found" in body or "the deployment could not be found" in body:
                    return True, "Vercel deployment missing (404 + DEPLOYMENT_NOT_FOUND)"

                if "x-vercel-id" in r.headers:
                    return True, "Vercel deployment missing (x-vercel-id header present on 404)"

            if "x-vercel-id" in r.headers and r.status_code != 200:
                return True, f"Vercel header present with status {r.status_code} (likely missing)"
        except requests.RequestException:
            pass
        return False, "Vercel backend check inconclusive (request failed)"