import re
from typing import List, Tuple

def parse_subzy_output(file_path: str) -> List[Tuple[str, str]]:
    """Parse Subzy output, return list of (domain, service_name)."""
    targets = []
    pattern = re.compile(r'^\[ VULNERABLE \]\s+-\s+(\S+)\s+\[\s*(.+?)\s*\]')
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            # Strip ANSI codes if present
            clean = re.sub(r'\x1b\[[0-9;]*m', '', line.strip())
            m = pattern.match(clean)
            if m:
                targets.append((m.group(1), m.group(2)))
    return targets