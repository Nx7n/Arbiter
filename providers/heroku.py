import requests
import re
from .base import BaseProvider
from typing import List, Tuple

class HerokuProvider(BaseProvider):
    cname_patterns = [r'\.herokuapp\.com$']
    error_regex = r'No such app'

    def verify_backend(self, domain: str, cname_chain: List[str]) -> Tuple[bool, str]:
        """
        Heroku returns a definitive 'No such app' error when the app doesn't exist.
        """
        try:
            r = requests.get(f"https://{domain}", timeout=5, allow_redirects=False,
                             headers={"User-Agent": "subtakeover-validator"})
            if r.status_code == 404 and re.search(r'no such app', r.text, re.IGNORECASE):
                return True, "Heroku app missing (404 + 'No such app')"
        except requests.RequestException:
            pass
        return False, "Heroku backend check inconclusive"