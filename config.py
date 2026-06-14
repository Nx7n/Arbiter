# Confidence thresholds
CONFIDENCE_CONFIRMED = 70
CONFIDENCE_LIKELY = 40
CONFIDENCE_SUSPICIOUS = 20

# Signal scores (adjust as needed)
SIGNAL_SCORES = {
    "vulnerable_provider_detected": 40,
    "error_page_fingerprint": 30,
    "nxdomain_backend": 20,
    "ssl_mismatch": 10,
    "service_api_confirms_missing": 50,
    "dangling_ns": 30,
    "expired_domain_in_chain": 25,
}

# HTTP settings
HTTP_TIMEOUT = 10
MAX_REDIRECTS = 5
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
]

# DNS settings
DNS_TIMEOUT = 5
DNS_LIFETIME = 10

