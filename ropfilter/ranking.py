# ropfilter/ranking.py
from __future__ import annotations
from typing import Dict, Tuple
from .utils import reg_match


def ret_rank_of(g) -> int:
    """
    Rank return type for sorting gadgets:
      0 = clean 'ret'         (best)
      1 = 'retn imm' variant  (middle)
      2 = no ret / dispatch   (worst)
    """
    if g.ret_imm is None:
        return 2   # no ret
    elif g.ret_imm == 0:
        return 0   # clean ret
    else:
        return 1   # retn imm


# ranking.py — add below memread_disp_rank/memwrite_disp_rank helpers

def reg2reg_disp_rank_via_lea(g, j: int) -> int:
    """
    Returns a displacement rank for reg2reg[j] **if** it originated from LEA,
    by locating the corresponding 'arith' entry (op='lea') and using its 'disp'.
    Fallbacks:
      - if kind != 'lea' → rank 0
      - if no matching arith/op='lea' found → rank 0
    Buckets (lower is better): 0 (0), 1 (<=8), 2 (<=32), 3 (<=128), 4 (else)
    """
    try:
        src, dst, kind = g.reg2reg[j]
    except Exception:
        return 0

    if kind != "lea":
        return 0

    # Find the closest arith entry that represents the same LEA (same dst/base)
    pos_list = getattr(g, "reg2reg_pos", []) or []
    anchor_idx = pos_list[j] if j < len(pos_list) else None

    best = None  # (delta, disp)
    for a in getattr(g, "arith", []) or []:
        if not isinstance(a, dict):
            continue
        if a.get("op") != "lea":
            continue
        if a.get("dst") != dst:
            continue
        if a.get("base") != src:
            continue

        ai = a.get("idx")
        disp = a.get("disp", 0) or 0
        # prefer the arith entry closest to the reg2reg instruction index
        if isinstance(anchor_idx, int) and isinstance(ai, int):
            delta = abs(ai - anchor_idx)
        else:
            delta = 0  # no index info → accept first match

        if best is None or delta < best[0]:
            best = (delta, disp)

    if best is None:
        return 0

    d = abs(int(best[1])) if best[1] is not None else 0
    if d == 0:
        return 0
    if d <= 8:
        return 1
    if d <= 32:
        return 2
    if d <= 128:
        return 3
    return 4


def _mem_disp_of(mem) -> tuple[int, int]:
    """
    Return (disp_rank, is_abs) for a single MemOp.
      [base]      -> (0, 0)
      [base+disp] -> (1, 0)
      [abs]       -> (2, 1)
    """
    if getattr(mem, "absolute", None) is not None:
        return (2, 1)
    if getattr(mem, "disp", None) is not None:
        return (1, 0)
    return (0, 0)


def memread_disp_rank(g, specs) -> tuple[int, int]:
    """
    Best displacement rank among this gadget's memreads that MATCH the user's specs.
    Only memreads satisfying dst/base (and abs if provided) are considered.
    If nothing matches, return worst (2, 1) so ranker treats it as least desirable.
    """
    best = (2, 1)  # worst by default
    for spec in (specs or []):
        want_dst  = spec.get("dst")
        want_base = spec.get("base")
        want_abs  = spec.get("abs")
        for mr in getattr(g, "memreads", []):
            # abs handling: if user asked abs, require exact equality
            if want_abs is not None:
                if mr.absolute != want_abs:
                    continue
            # pattern matching for dst/base
            if not reg_match(mr.dst,  want_dst):
                continue
            if want_abs is None and not reg_match(mr.base, want_base):
                continue
            best = min(best, _mem_disp_of(mr))
    return best


def memwrite_disp_rank(g, specs) -> tuple[int, int]:
    """
    Best displacement rank among this gadget's memwrites that MATCH the user's specs.
    Only memwrites satisfying src/base (and abs if provided) are considered.
    If nothing matches, return worst (2, 1).
    """
    best = (2, 1)
    for spec in (specs or []):
        want_src  = spec.get("src")
        want_base = spec.get("base")
        want_abs  = spec.get("abs")
        for mw in getattr(g, "memwrites", []):
            if want_abs is not None:
                if mw.absolute != want_abs:
                    continue
            if not reg_match(mw.src,  want_src):
                continue
            if want_abs is None and not reg_match(mw.base, want_base):
                continue
            best = min(best, _mem_disp_of(mw))
    return best


def make_weights(profile: str) -> Dict[str,float]:
    w = dict(instr=2.0, clobber=3.0, stack=2.0, addr_bad=3.0, weird=1.0, sem=1.0, dispatch_bonus=-2.0)
    if profile == "reg2reg":
        w.update(instr=3.0, clobber=3.5, sem=1.2)
    elif profile == "memread":
        w.update(instr=2.5, sem=1.4)
    elif profile == "memwrite":
        w.update(instr=2.5, sem=1.4)
    elif profile == "pivot":
        w.update(stack=2.5, clobber=3.5, sem=1.5)
    elif profile == "call":
        w.update(instr=2.0, sem=1.6)
    return w
