from dataclasses import dataclass
from typing import List, Dict
from enum import Enum

class Verdict(Enum):
    CONFIRMED = 1
    LIKELY = 2
    SUSPICIOUS = 3
    FALSE_POSITIVE = 4

def compute_confidence(signals: List[Dict]) -> int:
    """Sum signal scores, capped at 100."""
    total = sum(s.get("score", 0) for s in signals)
    return min(total, 100)