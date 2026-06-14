import random
import re
import requests
from typing import Tuple, Optional, Dict
from config import USER_AGENTS, HTTP_TIMEOUT

#=======================================================================
# Return (match, protocol, status_code) if error page pattern found
#=======================================================================

def check_http_error(domain: str, error_regex: str) -> Tuple[bool, Optional[str], Optional[int]]:
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    for protocol in ("https", "http"):
        url = f"{protocol}://{domain}"
        try:
            resp = requests.get(url, timeout=HTTP_TIMEOUT, allow_redirects=True,
                                verify=False, headers=headers)
            haystack = f"{resp.status_code} {resp.text} {str(resp.headers)}"
            if re.search(error_regex, haystack, re.IGNORECASE):
                return True, protocol, resp.status_code
        except Exception:
            continue
    return False, None, None

#=======================================================================
# Fetch headers and return them and a flag if CDN masking detected.
#=======================================================================

def analyse_headers(domain: str) -> Tuple[Dict[str, str], bool]:
    headers = {}
    cdn_detected = False
    try:
        resp = requests.get(f"https://{domain}", timeout=HTTP_TIMEOUT, allow_redirects=True, verify=False,
                            headers={"User-Agent": random.choice(USER_AGENTS)})
        headers = {k.lower(): v for k, v in resp.headers.items()}
        # Simple CDN detection via common headers
        if any(h in headers for h in ["cf-ray", "x-cdn", "x-amz-cf-id"]):
            cdn_detected = True
    except Exception:
        pass
    return headers, cdn_detected