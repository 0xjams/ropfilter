# ropfilter/popmap.py — v0.2.21-popmap (aligned with project utilities)
from __future__ import annotations

from typing import Dict, List, Optional, Tuple, Iterable, Any
from dataclasses import dataclass, field

from .constants import REGS
from .utils import canon_reg
from .ranking import ret_rank_of
from .output import gadget_to_text

# In this project, Gadget objects (models.Gadget) expose:
#   .address (int), .text (str), .instr_count (int|None), .ret_imm (int|None), .pops (List[str])
# We rely on those instead of re-implementing parsing.

@dataclass(order=True)
class PopCandidate:
    sort_index: Tuple[int, int, int] = field(init=False, repr=False)
    # primary sort: desirability (lower is better in key)
    rr: int
    instrs: int
    address: int
    # payload
    reg: str = field(compare=False)
    text: str = field(compare=False)
    ret_imm: Optional[int] = field(default=None, compare=False)
    extra_pops: int = field(default=0, compare=False)

    def __post_init__(self):
        # Sorting key: (ret_rank, instr_count, address)
        self.sort_index = (int(self.rr), int(self.instrs), int(self.address))

def _ret_only(gs: Iterable[Any]) -> List[Any]:
    """Keep gadgets that end with a RET/RETN (classifier sets .ret_imm)."""
    return [g for g in gs if getattr(g, "ret_imm", None) is not None]

def _target_pops(g) -> List[str]:
    """Return canonical 32-bit regs popped by gadget using classifier output."""
    out: List[str] = []
    pops = getattr(g, "pops", None) or []
    for r in pops:
        rc = canon_reg(str(r))
        if rc:
            out.append(rc)
    return out

def _extra_pop_count(g, target: str) -> int:
    pops = _target_pops(g)
    return sum(1 for r in pops if r != target)

def build_pop_map(gadgets: Iterable[Any], regs: Optional[List[str]], topk: int) -> Dict[str, List[PopCandidate]]:
    regs = [r for r in (regs or REGS) if r in REGS]
    buckets: Dict[str, List[PopCandidate]] = {r: [] for r in regs}

    for g in _ret_only(gadgets):
        text = getattr(g, "text", "") or ""
        addr = int(getattr(g, "address", 0) or 0)
        instrs = int(getattr(g, "instr_count", 0) or 0)
        rr = int(ret_rank_of(g))
        retn = getattr(g, "ret_imm", None)

        for r in _target_pops(g):
            if r not in buckets:
                continue
            cand = PopCandidate(rr=rr, instrs=instrs, address=addr, reg=r, text=text, ret_imm=retn,
                                extra_pops=_extra_pop_count(g, r))
            buckets[r].append(cand)

    # Sort & slice
    for r, lst in buckets.items():
        lst.sort()  # uses PopCandidate.sort_index
        if topk is not None and topk > 0:
            buckets[r] = lst[:topk]
    return buckets

def parse_popmap_arg(val: Optional[str]) -> Tuple[int, Optional[List[str]]]:
    """
    Accept:
      None/""     -> (5, None)  # default
      "N"         -> (N, None)
      "N/reg"     -> (N, [reg])
      "N/reg1,reg2" -> (N, [reg1, reg2])
      "reg" or "reg1,reg2" -> (5, [regs])
    """
    if val is None or val == "":
        return 5, None
    s = str(val).strip().lower()
    if "/" in s:
        n_part, r_part = s.split("/", 1)
        n = int(n_part.strip())
        regs = [canon_reg(x.strip()) for x in r_part.split(",")]
        regs = [r for r in regs if r]
        return n, (regs or None)
    # pure number?
    try:
        n = int(s)
        return n, None
    except Exception:
        pass
    # pure register list
    regs = [canon_reg(x.strip()) for x in s.split(",")]
    regs = [r for r in regs if r]
    return 5, (regs or None)

def pretty_print_popmap(args, popmap: Dict[str, List[PopCandidate]]) -> str:
    base = getattr(args, "base_addr", None)
    lines: List[str] = []
    for reg in [r for r in REGS if r in popmap]:  # stable reg order
        cands = popmap[reg]
        if not cands:
            continue
        lines.append(f"== POP → {reg} ==")
        for i, c in enumerate(cands, 1):
            # Reuse gadget_to_text so printing matches rest of tool
            # We also show a tiny meta trailer (retn, extra pops) for quick triage.
            trailer = []
            if c.ret_imm is not None:
                trailer.append(f"retn={c.ret_imm}")
            if c.extra_pops:
                trailer.append(f"+{c.extra_pops} extra POPs")
            meta = ("  [" + ", ".join(trailer) + "]") if trailer else ""
            lines.append(f"  {i:>2}. " + gadget_to_text(type("G", (), dict(address=c.address, text=c.text))(), base) + meta)
        lines.append("")
    return "\n".join(lines).rstrip()

def run_pop_map(args, all_gadgets, popmap_arg: Optional[str]):
    topk, regs = parse_popmap_arg(popmap_arg)
    popmap = build_pop_map(all_gadgets, regs=regs, topk=topk)
    print(f"# POP map (top {topk} per register)\n")
    print(pretty_print_popmap(args, popmap))
