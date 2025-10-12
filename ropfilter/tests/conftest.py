# tests/conftest.py
# Ensures the project root (which contains the 'ropfilter' package) is on sys.path
import os, sys
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
from types import SimpleNamespace

# Minimal MemOp object used by filters.gadget_matches
class MemOp:
    def __init__(self, *, dst=None, src=None, base=None, disp=None, absolute=None, op=None, idx=None):
        self.dst = dst
        self.src = src
        self.base = base
        self.disp = disp
        self.absolute = absolute
        self.op = op
        self.idx = idx

def mk_args(**over):
    """Namespace with all attributes gadget_matches may touch."""
    base = dict(
        addr_no_bytes=None,
        max_instr=None,
        ret_only=False,
        retn=None,
        max_stack_delta=None,
        strict_mem=False,   # tests set explicitly per case
        stable_dst=False,

        # parsed specs (lists)
        reg2reg_specs=[],
        memread_specs=[],
        memwrite_specs=[],
        arith=[],

        # pivots / dispatch / sequence / clobbers
        pivot=False, pivot_kind=None, pivot_reg=None, pivot_imm=None,
        call_reg=None, call_abs=None, call_mem=None,
        pop_seq=None,
        avoid_clobber=None, require_writes=None,

        debug=False,
    )
    base.update(over)
    return SimpleNamespace(**base)

def mk_gadget(**over):
    """Builds a minimal gadget-like object with attributes accessed by filters/solver."""
    default = dict(
        address=0x401000,
        instr_count=3,
        ret_imm=0,
        stack_delta=4,
        reg2reg=[],
        reg2reg_pos=[],
        memreads=[],
        memwrites=[],
        arith=[],
        pops=[],
        pop_pos=[],
        pivot=[],
        dispatch=[],
        clobbers=[],
        score=(None,),
        source="test.bin",
    )
    default.update(over)
    return SimpleNamespace(**default)

def mk_dispatch(*, kind="call", target="reg", reg=None, absolute=None):
    return SimpleNamespace(kind=kind, target=target, reg=reg, absolute=absolute)

def mk_pivot(*, kind="leave", reg="esp", imm=0):
    return SimpleNamespace(kind=kind, reg=reg, imm=imm)

# export for tests
__all__ = ["MemOp", "mk_args", "mk_gadget", "mk_dispatch", "mk_pivot"]
