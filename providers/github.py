import re
import requests
from .base import BaseProvider
from typing import List, Tuple

class GitHubProvider(BaseProvider):
    cname_patterns = [r'\.github\.io$']
    error_regex = r"There isn't a GitHub Pages site here"

    def verify_backend(self, domain: str, cname_chain: List[str]) -> Tuple[bool, str]:
        """
        Try to reconstruct the GitHub repository URL from the CNAME chain
        and check if it exists. For user pages (<user>.github.io),
        the repo is <user>/<user>.github.io.
        """

        gh_cname = next((c for c in cname_chain if '.github.io' in c), domain)
        
        match = re.match(r'^([^.]+)\.github\.io$', gh_cname, re.IGNORECASE)
        if not match:
            return False, "Cannot parse GitHub user from CNAME"

        user = match.group(1).lower()
        repo = f"{user}.github.io"  
        url = f"https://github.com/{user}/{repo}"

        try:
            r = requests.head(url, timeout=5, allow_redirects=True)
            if r.status_code == 404:
                return True, f"GitHub repository '{user}/{repo}' not found (404)"
            else:
                return False, f"Repository exists (HTTP {r.status_code}), but Pages may not be active"
        except requests.RequestException:
            pass
        return False, "GitHub backend check inconclusive (network error)"