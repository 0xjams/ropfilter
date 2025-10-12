# ropfilter/cli.py
from __future__ import annotations
import argparse
import textwrap

from .utils import parse_kvlist

# -----------------------------
# Small helpers for CLI parsing
# -----------------------------

def _int0(x: str) -> int:
    """Parse int with base auto-detection (0x.., decimal)."""
    return int(x, 0)

def _csv_list(s: str) -> list[str]:
    """Split a,b,c → ['a','b','c'] (lowercased, stripped), empty→[]."""
    if not s:
        return []
    return [t.strip().lower() for t in s.split(",") if t.strip()]

def _parse_badbytes(s: str) -> list[int]:
    """
    Parse bad bytes list for address filtering.
    Accepts '00,0a,ff' or '0x00,0xff' forms.
    """
    out = []
    for tok in _csv_list(s):
        if tok.startswith("\\x") and len(tok) == 4:
            out.append(int(tok[2:], 16))
        else:
            out.append(int(tok, 16))
    return out

def _parse_reg2reg(items: list[str]) -> list[tuple[str, str]]:
    """
    Parse reg2reg specs of the form 'SRC->DST'.
    Supports negation/alternation per REGPAT (e.g., 'eax|ecx->!ebx|esi').
    """
    specs = []
    for it in items or []:
        s = it.strip()
        if "->" not in s:
            continue
        src, dst = s.split("->", 1)
        specs.append((src.strip().lower(), dst.strip().lower()))
    return specs

def _parse_mem_specs(items: list[str]) -> list[dict]:
    """
    Parse memread/memwrite specs using utils.parse_kvlist (which supports
    keys like 'base', 'dst', 'src', 'op', 'abs', and the displacement forms:
    'disp', 'disp>', 'disp>=', 'disp<', 'disp<=')
    """
    out = []
    for it in items or []:
        kv = parse_kvlist(it)
        # normalize keys to lowercase handled in parse_kvlist; keep as-is
        out.append(kv)
    return out


# -----------------------------
# Argument builder
# -----------------------------

def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ropfilter",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Filter and chain ROP gadgets from rp++-style dumps.",
        epilog=textwrap.dedent("""
        Examples:
          # Simple reg move:
          -f app_rop.txt --reg2reg 'esp->eax'

          # Memory read/write with displacement constraints:
          --memread  'dst=eax,base=ecx,disp>=0x10,disp<0x40'
          --memwrite 'src=edx,base=esi,disp> = 0'

          # Arithmetic with memory participants (dst_mem/src_mem):
          --arith 'op=add,dst=esi,src_base=eax,src_disp<=0'

          # Exact register names (eax != ax != al) everywhere:
          --exact-reg

          # Solver (JSON/YAML file), find regx/regy s.t. reachability and a memwrite hold:
          --solve-file spec.yaml
        """).strip()
    )

    # 0) Required input
    gi = p.add_argument_group("Input")
    gi.add_argument("-f", "--file", required=True, nargs="+",
                help="Path(s) to rp++-style gadget text file(s)")

    gi.add_argument("--base-addr", type=_int0, default=None, help="Base address for 'Base + 0x...' formatting")

    # 1) Core filters & execution limits
    gf = p.add_argument_group("Core filters & limits")
    gf.add_argument("--addr-no-bytes", type=_parse_badbytes, default=None,
                    help="Comma-separated bad bytes not allowed in gadget address (e.g., '00,0a,0d,ff').")
    gf.add_argument("--max-instr", type=int, default=None, help="Maximum instruction count per gadget")
    gf.add_argument("--ret-only", action="store_true", help="Require bare 'ret' (retn 0)")
    gf.add_argument("--retn", type=_int0, default=None, help="Require 'retn N' with immediate N return retn with imm < N")
    gf.add_argument("--protect-stack", action="store_true", help="drop gadgets with pushes more than pops")
    gf.add_argument("--max-stack-delta", type=int, default=None, help="Maximum allowed stack delta")
    gf.add_argument("--stable-dst", action="store_true", default=False,
                    help="If set, reject gadgets where the matched DST register is overwritten later "
                         "with a different value (smart, order-aware). Default: off.")
    gf.add_argument(
        "--stable-src",
        action="store_true",
        default=False,
        help="Reject gadgets where the source register is overwritten *before* the matched instruction."
    )
    gf.add_argument("--exact-reg", action="store_true",
                    help="Match exact register names (no sub-register aliasing).")
    gf.add_argument("--strict-mem", action="store_true", default=False,
                    help="Reject any gadget that uses absolute memory reference [0x...].")

    # In build_arg_parser(), after the existing Output & ranking flags:
    gf.add_argument(
        "--safe-enable",
        action="store_true",
        help="Enable a safe preset: --protect-stack --stable-dst --stable-src --strict-mem --exact-reg",
    )



    # 2) Register transfer filters
    gr = p.add_argument_group("Register transfers")
    gr.add_argument("--reg2reg", action="append", default=[],
                    help="Filter gadgets that move/copy between registers. "
                         "Format: 'SRC->DST' where SRC/DST are REGPATs (e.g., 'eax|ecx->!ebx'). "
                         "May be provided multiple times.")

    # 3) Memory access filters
    gm = p.add_argument_group("Memory operations (memread/memwrite)")
    gm.add_argument("--memread", action="append", default=[],
                    help=textwrap.dedent("""\
                    Match memory reads into registers. Repeatable.
                    Format: dst=REGPAT, base=REGPAT, abs=0xADDR, op=OP,
                            disp=INT, disp>INT, disp>=INT, disp<INT, disp<=INT
                    """).strip())
    gm.add_argument("--memwrite", action="append", default=[],
                    help=textwrap.dedent("""\
                    Match memory writes from registers. Repeatable.
                    Format: src=REGPAT, base=REGPAT, abs=0xADDR, op=OP,
                            disp=INT, disp>INT, disp>=INT, disp<INT, disp<=INT
                    """).strip())

    # 4) Arithmetic filters
    ga = p.add_argument_group("Arithmetic / logical operations (--arith)")
    ga.add_argument("--arith", action="append", default=[],
                    help=textwrap.dedent("""\
                    Match arithmetic/logical ops. Repeatable. Parsed as key-value list.
                    Keys:
                      op=add|sub|xor|or|and|adc|sbb|imul|neg|inc|dec|lea|xadd|...
                      dst=REGPAT, src=REGPAT, imm=INT
                    Memory participants (optional):
                      dst_base=REGPAT, dst_abs=ADDR,
                      dst_disp=INT | dst_disp>INT | dst_disp>=INT | dst_disp<INT | dst_disp<=INT
                      src_base=REGPAT, src_abs=ADDR,
                      src_disp=INT | src_disp>INT | src_disp>=INT | src_disp<INT | src_disp<=INT
                    """).strip())

    # 5) Dispatch & pivot filters
    gd = p.add_argument_group("Dispatch & pivot")
    gd.add_argument("--call-reg", default=None, help="Require call/jmp via register (e.g., 'eax')")
    gd.add_argument("--call-abs", type=_int0, default=None, help="Require call/jmp absolute address (int/hex)")
    gd.add_argument("--call-mem", default=None, help="Require call/jmp [REG] style (base register)")
    gd.add_argument("--pivot", action="store_true", help="Require gadget to be a stack pivot")
    gd.add_argument("--pivot-kind", choices=["xchg", "mov", "add", "leave"], help="Restrict pivot kind")
    gd.add_argument("--pivot-reg", default=None, help="Pivot controlling register (e.g., 'eax')")
    gd.add_argument("--pivot-imm", type=_int0, default=None, help="Immediate for arithmetic pivots")

    # 6) Sequence / clobber constraints
    gs = p.add_argument_group("Sequence / clobber constraints")
    gs.add_argument("--pop-seq", type=_csv_list, default=None,
                    help="Require a subsequence of pops (comma-separated regs, exact order)")
    gs.add_argument("--avoid-clobber", type=_csv_list, default=None,
                    help="Drop gadgets that clobber any of these registers")
    gs.add_argument("--require-writes", type=_csv_list, default=None,
                    help="Require that all these registers are written by the gadget")
    gs.add_argument("--avoid-memref", type=str, default=None,
                    help=textwrap.dedent("""
                        Avoid gadgets that contain memory references using specified base registers.
                        Patterns:\n
                          *           → avoid all memory references\n
                          eax         → avoid memory references using eax as the base\n
                          eax|ebx     → avoid memory references using eax or ebx as the base\n
                          !eax|ebx    → allow ONLY eax or ebx as base (avoid all others)\n
                        Special rule: when using '*', explicit base constraints from other filters\n
                        (base= in --memread/--memwrite, or src_base=/dst_base= in --arith)\n
                        override the avoidance for the specified base(s).
                    """).strip())

    # 7) Chaining & maps
    gc = p.add_argument_group("Chaining & maps")
    gc.add_argument("--chain", action="store_true", help="Enable chain search when single gadget fails")
    gc.add_argument("--chain-max-steps", type=int, default=3,
                   help="Max gadgets in a synthesized chain (default: 3).")
    gc.add_argument("--chain-allow", type=lambda s: [t.strip().lower() for t in s.split(",") if t.strip()],
                   help="Allowed temporary registers during chaining (default: all GPRs except esp).")
    gc.add_argument("--chain-limit", type=int, default=10,
                   help="Max number of synthesized chains to print (default: 10).")
    gc.add_argument("--reg-map", type=str, help="Print register transfer map instead of gadgets")
    gc.add_argument("--pop-map", nargs="?", const="", metavar="N/REGS",
                help="Print POP gadgets per register. Forms: N, N/REG or N/REG1,REG2, or just REG1,REG2; empty => top 5 all.")


    # 8) Solver (JSON/YAML)
    gsolve = p.add_argument_group("Constraint solver (JSON/YAML)")
    gsolve.add_argument("--solve-json",
        help="Inline JSON solve spec.")
    gsolve.add_argument("--solve-file",
        help="Path to JSON/YAML spec. YAML requires PyYAML.")
    gsolve.add_argument("--solve-max-solutions", type=int, default=10,
        help="Maximum number of solutions from the solver")

    # 9) Output, ranking & misc
    go = p.add_argument_group("Output & ranking")
    go.add_argument("--best-last", action="store_true", help="Print highest-ranked gadgets last")
    go.add_argument("--limit", type=int, default=None, help="Limit number of printed gadgets")
    go.add_argument("--out", choices=["text", "json", "python"], default="text", help="Output format")
    go.add_argument("--debug", action="store_true", help="Verbose debug logs")
    go.add_argument(
        "--debug-file",
        metavar="PATH",
        help="Write JSONL debug trace of the solve process to PATH (optional).",
        default=None,
    )
    return p


