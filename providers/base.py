from abc import ABC, abstractmethod
from typing import List, Tuple

class BaseProvider(ABC):
    # List of CNAME regex patterns that indicate this provider
    cname_patterns: List[str] = []

    # Regex to detect error page in HTTP response
    error_regex: str = ""

    @abstractmethod
    def verify_backend(self, domain: str, cname_chain: List[str]) -> Tuple[bool, str]:
        """
        Return (is_missing, explanation).
        is_missing = True if the backend resource is confirmed missing/available for takeover.
        """
        pass