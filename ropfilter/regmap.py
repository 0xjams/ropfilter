# ropfilter/regmap.py
"""
Register transfer map analysis.

Given a set of gadgets, explore which registers can transfer into which
(register-to-register). Shows top X best gadgets per pair, optionally using
chain search to fill gaps.
"""
from __future__ import annotations


import argparse
from .constants import REGS
from .ranking import ret_rank_of
from .output import gadget_to_text
from . import chain as chainmod
from .filters import gadget_matches


# ANSI colors for notes
#GREEN = "\x1b[92m"
#YELLOW = "\x1b[93m"
#RESET = "\x1b[0m"
GREEN = ""
YELLOW = ""
RESET = ""

# NEW: keep only gadgets that end with a RET (plain or with an immediate)
def _ret_only(gs):
    """Return only gadgets whose classifier set a non-None ret_imm (i.e., 'ret' or 'retn imm')."""
    return [g for g in gs if getattr(g, "ret_imm", None) is not None]

def _rank_reg2reg_gadgets(gs):
    """Sort gadgets by desirability: ret form, instr_count, then address."""
    def key(g):
        return (ret_rank_of(g), g.instr_count or 0, g.address)
    return sorted(gs, key=key)

def run_reg_map(args, all_gadgets, X, restrict_src=None):
    """
    For each source register, list dst pairs with up to X best direct reg2reg gadgets.
    If --chain is set and fewer than X gadgets exist, print chain candidates.
    If restrict_src is provided, only map transfers starting from that register.
    """
    # normalize/validate restrict_src
    if restrict_src:
        restrict_src = restrict_src.lower()
        if restrict_src not in REGS:
            raise SystemExit(f"--reg-map: unknown register {restrict_src!r}. "
                             f"Use one of: {', '.join(REGS)}")

    print(f"# Register transfer map (top {X} per pair){' with chains' if args.chain else ''}\n")
    all_gadgets = _ret_only(all_gadgets)


    # We ignore operation-specific filters so the map reflects pure transfer capability,
    # but still respect global constraints (ret, max-instr, bad-bytes, strict-mem, clobbers)
    def make_args_for_pair(src, dst):
        temp = argparse.Namespace(**vars(args))
        temp.reg2reg_specs = [(src, dst)]
        # Disable unrelated operation-specific filters
        temp.memread_specs = []
        temp.memwrite_specs = []
        temp.arith_specs = []
        temp.pivot_reg = None
        temp.pivot_kind = None
        temp.call_reg = None
        temp.call_abs = None
        temp.call_mem = None
        temp.pop_seq = None
        return temp

    # Helper: does any transfer exist for (src, dst)? (direct or chain if allowed)
    from .filters import gadget_matches
    def has_transfer(src, dst):
        temp = make_args_for_pair(src, dst)
        # Direct
        for g in all_gadgets:
            if gadget_matches(g, temp):
                return True
        # Chain
        if args.chain:
            ch = chainmod.find_reg_chain(src, dst, all_gadgets, temp)
            return bool(ch)
        return False

    # Precompute reverse availability map for colored notes
    reverse_ok = {}
    for s in REGS:
        for d in REGS:
            if s == d:
                continue
            reverse_ok[(s, d)] = has_transfer(s, d)

    # Now print grouped by source register
    srcs = REGS
    if restrict_src:
        srcs = [restrict_src]

    for src in srcs:
        print(f"=== {src} ===")
        print()
        for dst in REGS:
            if src == dst:
                continue

            temp = make_args_for_pair(src, dst)
            # Direct gadgets
            direct = [g for g in all_gadgets if gadget_matches(g, temp)]
            direct_sorted = _rank_reg2reg_gadgets(direct)

            shown = 0
            # Header with colored reverse note (if reverse exists)
            rev_note = f" {GREEN}[reverse {dst}->{src} OK]{RESET}" if reverse_ok.get((dst, src), False) else ""
            print(f"== {src} -> {dst} =={rev_note}")

            # Print direct gadgets
            for g in direct_sorted[:X]:
                print("  - " + gadget_to_text(g, getattr(args, "base_addr", None)))
                shown += 1

            # Chains if needed
            if shown < X and args.chain:
                remaining = X - shown
                chains = chainmod.find_reg_chain(src, dst, all_gadgets, temp)
                for path in chains[:remaining]:
                    print(f"  - CHAIN ({len(path)} step{'s' if len(path)!=1 else ''}):")
                    for pg in path:
                        print("      * " + gadget_to_text(pg, getattr(args, "base_addr", None)))
                    shown += 1
                    if shown >= X:
                        break

            if shown == 0:
                print("  (no direct gadgets" + ("" if not args.chain else " or short chains") + ")")

            print()  # blank line between dst pairs

        # separator between source groups
        print()
