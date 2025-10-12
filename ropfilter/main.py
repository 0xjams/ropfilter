# ropfilter/main.py
# ropfilter/main.py
# ropfilter/main.py
from __future__ import annotations
import json
from typing import List



# Support both:
#   1) python3 -m ropfilter        (package mode)
#   2) python3 ropfilter/main.py   (direct script from inside the package dir)
if __package__ is None or __package__ == "":
    # Running as a script: add the parent of this file (the project root) to sys.path
    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from ropfilter.cli import build_argparser
    from ropfilter.parsing import parse_file
    from ropfilter.filters import gadget_matches
    from ropfilter.utils import norm_reg, parse_reg2reg_spec, parse_kvlist, bytestr_to_set, set_exact_reg_mode, pretty_print_object, now, elapsed_since
    from ropfilter.ranking import ret_rank_of, memread_disp_rank, memwrite_disp_rank
    from ropfilter.output import gadget_to_text, _fmt_addr
    from ropfilter.chain import find_reg_chain, find_memread_chain, find_memwrite_chain, find_arith_chain
    from ropfilter.solver import load_solve_spec, solve, print_solutions
    from ropfilter.popmap import run_pop_map  # v0.2.21-popmap
    from ropfilter.regmap import run_reg_map    
    from ropfilter.cache_sqlite import parse_file_cached
    import atexit
else:
    # Running as a package via -m
    from .cli import build_argparser
    from .parsing import parse_file
    from .filters import gadget_matches
    from .utils import norm_reg, parse_reg2reg_spec, parse_kvlist, bytestr_to_set,set_exact_reg_mode, pretty_print_object, now, elapsed_since
    from .ranking import ret_rank_of, memread_disp_rank, memwrite_disp_rank
    from .output import gadget_to_text, _fmt_addr
    from .chain import find_reg_chain, find_memread_chain, find_memwrite_chain, find_arith_chain
    from .solver import load_solve_spec, solve, print_solutions
    from .popmap import run_pop_map  # v0.2.21-popmap
    from .regmap import run_reg_map
    # ropfilter/main.py — add near other imports
    from .cache_sqlite import parse_file_cached
    import atexit





def run():
    ap = build_argparser()
    args = ap.parse_args()

    # ---- simple end-to-end timer ----
    _t0 = now()
    atexit.register(lambda: print(f"[time] total: {elapsed_since(_t0)}"))

    if getattr(args, "safe_enable", False):
        args.protect_stack = True
        args.stable_dst = True
        args.stable_src = True
        args.strict_mem = True
        args.exact_reg = True

    set_exact_reg_mode(getattr(args, "exact_reg", False))

    if getattr(args, 'legacy_no_strict_mem', False):
        # Old flag explicitly requested "no strict" → force strict_mem False
        args.strict_mem = False
    setattr(args, 'no_strict_mem', not bool(getattr(args, 'strict_mem', False)))

    # Normalize/expand CLI
    args.reg2reg_specs  = [parse_reg2reg_spec(s) for s in args.reg2reg]
    args.memread_specs  = [parse_kvlist(s) for s in args.memread]
    args.memwrite_specs = [parse_kvlist(s) for s in args.memwrite]
    args.arith_specs =    parse_kvlist(args.arith[0] if args.arith else None )

    if args.pivot_reg: args.pivot_reg = norm_reg(args.pivot_reg)
    if args.call_reg:  args.call_reg  = norm_reg(args.call_reg)
    if args.call_mem:  args.call_mem  = norm_reg(args.call_mem)
    if args.avoid_clobber:
        args.avoid_clobber = [norm_reg(r) for r in args.avoid_clobber if norm_reg(r)]
    if args.require_writes:
        args.require_writes = [norm_reg(r) for r in args.require_writes if norm_reg(r)]
    if args.addr_no_bytes and not isinstance(args.addr_no_bytes, list):
        args.addr_no_bytes = bytestr_to_set(args.addr_no_bytes)

    # Load gadgets (with sqlite cache)
    gadgets: List = []
    _exact = bool(getattr(args, "exact_reg", False))
    for path in args.file:
        # include only args that affect parsing/classification in the cache key if needed
        gadgets.extend(parse_file_cached(path, exact_reg=_exact, extra_args={}))

        
    '''
    for g in gadgets:
        if g.text == 'lea ebp, dword [esp+0x0c] ; push eax ; ret':
            pretty_print_object(g)
    '''
    # --- Parse --reg-map option ---
    reg_map_X = None
    reg_map_reg = None
    if getattr(args, "reg_map", None):
        try:
            if "," in args.reg_map:
                num, reg = args.reg_map.split(",", 1)
                reg_map_X = int(num.strip())
                reg_map_reg = reg.strip().lower()
            else:
                reg_map_X = int(args.reg_map.strip())
        except Exception as e:
            raise SystemExit(f"Invalid --reg-map value {args.reg_map!r}: must be N or N,REG")

    if reg_map_X:
        run_reg_map(args, gadgets, reg_map_X, reg_map_reg)
        return

    # --- Parse --pop-map option ---
    pop_map_val = getattr(args, 'pop_map', None)
    if pop_map_val is not None:
        # We delegate parsing to popmap.run_pop_map itself (it prints output).
        run_pop_map(args, gadgets, pop_map_val)
        return

    # Solver mode: JSON/YAML constraint solving
    if getattr(args, "solve_json", None) or getattr(args, "solve_file", None):
        spec = load_solve_spec(getattr(args, "solve_json", None), getattr(args, "solve_file", None))
        sols = solve(spec, gadgets, args)
        print_solutions(sols, args, getattr(args, "base_addr", None))
        return

    # Direct match
    matched = [g for g in gadgets if gadget_matches(g, args)]




    # Synthesis (if enabled)
    if args.chain:
        paths: list[list] = []

        # Try chain synthesis when specific positive specs are present.
        # (Order matters; only one category at a time in CLI.)
        if getattr(args, "reg2reg_specs", None):
            for (src, dst) in args.reg2reg_specs:
                paths += find_reg_chain(src, dst, gadgets, args)

        elif getattr(args, "memread_specs", None):
            for spec in args.memread_specs:
                paths += find_memread_chain(spec.get("dst"), spec.get("base"), gadgets, args)

        elif getattr(args, "memwrite_specs", None):
            for spec in args.memwrite_specs:
                paths += find_memwrite_chain(spec.get("src"), spec.get("base"), gadgets, args)

        elif getattr(args, "arith", None):
            for kv in args.arith:
                paths += find_arith_chain(args.arith_specs, gadgets, args)

        # If we found any chain paths, print them and exit early.
        if paths:
            print("[chain] synthesized candidate chains (best first):")
            limit = getattr(args, "chain_limit", 10) or 10
            for path in paths[:limit]:
                addrs = "  ->  ".join(f"{_fmt_addr(g.address, getattr(args, 'base_addr', None))}" for g in path)
                print(addrs)
                print("    " + "  ->  ".join(getattr(g, "text", "?") for g in path))
            return

    # Ranking (best last)
    if args.best_last:
        ranked = []
        for g in matched:
            if args.memwrite_specs:
                disp_rank, is_abs = memwrite_disp_rank(g, args.memwrite_specs)
            elif args.memread_specs:
                disp_rank, is_abs = memread_disp_rank(g, args.memread_specs)
            else:
                disp_rank, is_abs = (0, 0)
            rrank  = ret_rank_of(g)
            length = g.instr_count or 0
            key = (disp_rank, rrank, length, is_abs, g.address)
            ranked.append((key, g))
            if args.debug:
                print(f"[DEBUG] {gadget_to_text(g)} | disp_rank={disp_rank}, "
                        f"ret_rank={rrank}, instrs={length}")
                print("-"*30)
        ranked.sort(key=lambda x: x[0])
        matched = [g for _, g in ranked]
        matched.reverse()  # best last

    # Output
    if args.out == "json":
        print(json.dumps([{
            "address": f"0x{g.address:08x}",
            "text": g.text,
            "instr_count": g.instr_count,
            "ret_imm": g.ret_imm,
            "stack_delta": g.stack_delta,
            "reg2reg": g.reg2reg,
            "memreads": [vars(m) for m in g.memreads],
            "memwrites":[vars(m) for m in g.memwrites],
            "zero": g.zero,
            "arith": g.arith,
            "pops": g.pops,
            "pivot": [vars(p) for p in g.pivot],
            "dispatch": [vars(d) for d in g.dispatch],
            "clobbers": g.clobbers,
            "source": g.source,
        } for g in (matched[-args.limit:] if args.limit else matched)], indent=2))
    elif args.out == "python":
        print("gadgets = []")
        seq = matched[-args.limit:] if args.limit else matched
        for g in seq:
            print(f"gadgets.append({{'addr':'0x{g.address:08x}','text':{g.text!r},'src':{g.source!r},'score':None}})")
        print("print(f'Loaded {len(gadgets)} gadgets')")
    else:
        seq = matched[-args.limit:] if args.limit else matched
        for g in seq:
            pass
            print(gadget_to_text(g, getattr(args, "base_addr", None)))

if __name__ == "__main__":
    run()