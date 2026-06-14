import ssl
import socket
from typing import List, Dict, Optional
from config import SIGNAL_SCORES

def get_tls_signals(domain: str, chain: List[str]) -> List[Dict]:
    """Return list of TLS‑related signals."""
    signals = []
    cert = get_certificate(domain)
    if not cert:
        return signals

    # SAN mismatch check
    try:
        from cryptography import x509  
    except ImportError:
        # Fallback: check subject CN and SAN via ssl library
        subject = dict(x[0] for x in cert.get('subject', []))
        cn = subject.get('commonName', '')
        # Simple check: if the domain is not in CN
        if domain not in cn:
            signals.append({
                "name": "ssl_mismatch",
                "score": SIGNAL_SCORES["ssl_mismatch"],
                "description": f"Certificate CN '{cn}' does not match domain '{domain}'"
            })

        return signals

    # SAN parsing not implemented as of now, this is a placeholder for SAN parsing
    return signals

def get_certificate(domain: str) -> Optional[dict]:
    """Retrieve server certificate and return as dict of fields."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            return cert
    except Exception:
        pass
    return None