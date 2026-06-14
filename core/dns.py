import dns.resolver
import dns.exception
from typing import List, Optional

def resolve_chain(domain: str, resolver: dns.resolver.Resolver) -> List[str]:
    """Return full CNAME chain as list of targets."""
    chain = []
    current = domain
    seen = set()
    while True:
        try:
            answers = resolver.resolve(current, 'CNAME')
            cname = str(answers[0].target).rstrip('.')
            if cname in seen:  # loop
                break
            seen.add(cname)
            chain.append(cname)
            current = cname
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.LifetimeTimeout, dns.exception.DNSException):
            break
    return chain

def check_dangling_ns(domain: str, resolver: dns.resolver.Resolver) -> bool:
    """Return True if domain has NS records pointing to non‑existent nameservers."""
    try:
        answers = resolver.resolve(domain, 'NS')
        for ns in answers:
            ns_str = str(ns.target).rstrip('.')
            try:
                # Try resolving the nameserver itself
                resolver.resolve(ns_str, 'A')
            except dns.resolver.NXDOMAIN:
                return True
    except Exception:
        pass
    return False

def is_domain_expired(domain: str) -> bool:
    """Check WHOIS for domain expiry / availability."""
    try:
        import whois
        w = whois.whois(domain)
        if w.status is None and w.expiration_date is None:
            return True  
        if w.expiration_date:
            from datetime import datetime
            if isinstance(w.expiration_date, list):
                return any(d < datetime.now() for d in w.expiration_date)
            return w.expiration_date < datetime.now()
    except Exception:
        pass
    return False

def is_target_nxdomain(cname: str, resolver: dns.resolver.Resolver) -> bool:
    """Return True if the given CNAME target does not resolve (A/AAAA)."""
    try:
        resolver.resolve(cname, 'A')
        return False
    except dns.resolver.NXDOMAIN:
        return True
    except Exception:
        return False