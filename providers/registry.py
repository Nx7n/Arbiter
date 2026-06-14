import os
import importlib
import pkgutil
from providers.base import BaseProvider



_providers = []

def load_providers():
    """Dynamically load all provider classes from the providers package."""
    global _providers
    if _providers:
        return _providers

    # Manually register the built‑in ones
    from providers.github import GitHubProvider
    from providers.vercel import VercelProvider
    from providers.netlify import NetlifyProvider
    from providers.heroku import HerokuProvider
    from providers.s3 import S3Provider
    from providers.fingerprint import GenericFingerprintProvider


    _providers = [GitHubProvider(), VercelProvider(), NetlifyProvider(), HerokuProvider(), S3Provider(), GenericFingerprintProvider()]
    return _providers

def get_provider_for_cname(cname: str) -> BaseProvider | None:
    """Return the first provider whose CNAME pattern matches."""
    import re
    for provider in load_providers():
        for pattern in provider.cname_patterns:
            if re.search(pattern, cname, re.IGNORECASE):
                return provider
    return None