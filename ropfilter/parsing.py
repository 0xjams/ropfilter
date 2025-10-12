# ropfilter/parsing.py
from __future__ import annotations
import re
from typing import List, Optional
from .models import Gadget
from .classify import classify_gadget
from .constants import BANNED_PATTERNS
from .utils import clean

HEX_ADDR_RE = re.compile(r"^\s*0x([0-9a-fA-F]+)\s*:")
TAIL_FOUND_RE = re.compile(r";\s*\(\d+\s+found\)\s*$", re.IGNORECASE)

def parse_address(line: str) -> Optional[int]:
    m = HEX_ADDR_RE.match(line)
    return int(m.group(1),16) if m else None

def tokenize_instrs(rest: str) -> List[str]:
    rest = TAIL_FOUND_RE.sub("", rest.strip())
    parts = [p.strip() for p in rest.split(";") if p.strip()]
    return [p.lower() for p in parts]

def is_banned_instr(ins: str) -> bool:
    for rx in BANNED_PATTERNS:
        if rx.search(ins):
            return True
    return False

def parse_file(path: str) -> List[Gadget]:
    out: List[Gadget] = []
    with open(path, "r", errors="ignore") as f:
        for line in f:
            if not line or not line.lstrip().startswith("0x"): continue
            m = parse_address(line)
            if m is None: continue
            _, rest = line.split(":", 1)
            instrs = tokenize_instrs(rest)
            if not instrs: continue
            if any(is_banned_instr(ins) for ins in instrs):
                continue
            g = classify_gadget(m, instrs)
            g.source = path
            out.append(g)

    return out
