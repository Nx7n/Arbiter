import json
from typing import List, Tuple

def parse_subjack_output(file_path: str) -> List[Tuple[str, str]]:
    """Parse Subjack JSON output."""
    with open(file_path) as f:
        data = json.load(f)
    targets = []
    for entry in data:
        if entry.get("vulnerable"):
            targets.append((entry["domain"], entry.get("service", "")))
    return targets