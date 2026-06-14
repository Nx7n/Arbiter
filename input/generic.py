from typing import List, Tuple

def parse_generic_list(file_path: str) -> List[Tuple[str, str]]:
    """Read plaintext list of domains (one per line)."""
    with open(file_path) as f:
        return [(line.strip(), "") for line in f if line.strip()]