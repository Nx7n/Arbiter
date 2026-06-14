import re
import requests
import dns.resolver
from .base import BaseProvider
from typing import List, Tuple

class S3Provider(BaseProvider):
    cname_patterns = [r'\.s3-website[-\.].*\.amazonaws\.com$', r'\.s3\.amazonaws\.com$']
    error_regex = r'NoSuchBucket|The specified bucket does not exist'

    def verify_backend(self, domain: str, cname_chain: List[str]) -> Tuple[bool, str]:
        """
        Determine the S3 bucket endpoint from the CNAME chain and perform an
        anonymous HEAD request. HTTP 404 with 'NoSuchBucket' means the bucket is missing.
        """
        # Find the S3 CNAME
        s3_cname = None
        for cname in cname_chain:
            if re.search(r'\.s3(?:-website)?[-.]', cname):
                s3_cname = cname
                break

        if not s3_cname:
            return False, "No S3 CNAME found in chain"

        # Reconstruct bucket endpoint
        # Case 1: <bucket>.s3.amazonaws.com
        match = re.match(r'^([^.]+)\.s3\.amazonaws\.com$', s3_cname, re.IGNORECASE)
        if match:
            bucket = match.group(1)
            url = f"https://{bucket}.s3.amazonaws.com"
        else:
            # Case 2: <bucket>.s3-website-<region>.amazonaws.com
            match = re.match(r'^([^.]+)\.s3-website[-\.].*\.amazonaws\.com$', s3_cname, re.IGNORECASE)
            if match:
                bucket = match.group(1)
                # Need to preserve full endpoint for website hosting
                url = f"http://{s3_cname}"  # website endpoints use HTTP
            else:
                return False, f"Unrecognized S3 CNAME format: {s3_cname}"

        try:
            r = requests.head(url, timeout=5, allow_redirects=False,
                              headers={"Host": s3_cname})
            if r.status_code == 404:
                # Confirm NoSuchBucket body
                r2 = requests.get(url, timeout=5, headers={"Host": s3_cname})
                if re.search(r'NoSuchBucket', r2.text, re.IGNORECASE):
                    return True, f"S3 bucket '{bucket}' confirmed missing (NoSuchBucket)"
            elif r.status_code == 200:
                return False, f"S3 bucket '{bucket}' exists (HTTP 200)"
            elif r.status_code == 403:
                return False, f"S3 bucket '{bucket}' exists but is private (HTTP 403)"
        except requests.RequestException:
            pass

        return False, "S3 backend check inconclusive"