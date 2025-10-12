import pytest
from ropfilter.tests.conftest import MemOp, mk_args, mk_gadget

def test_memread_match_then_avoid_star_exempts_that_instr():
    g = mk_gadget(memreads=[MemOp(dst="eax", base="ebx", disp=4, idx=10, op="mov")])
    args = mk_args(memread_specs=[{"dst":"eax"}], avoid_memref="*")
    from ropfilter.filters import gadget_matches
    assert gadget_matches(g, args) is True

def test_memread_match_but_other_memref_blocks():
    g = mk_gadget(memreads=[
        MemOp(dst="eax", base="ebx", disp=4, idx=10, op="mov"),
        MemOp(dst="ecx", base="esi", disp=8, idx=11, op="mov"),
    ])
    args = mk_args(memread_specs=[{"dst":"eax"}], avoid_memref="*")
    from ropfilter.filters import gadget_matches
    assert gadget_matches(g, args) is False

def test_memwrite_match_then_avoid_specific_base_exempts_matched_write():
    g = mk_gadget(memwrites=[MemOp(src="ecx", base="ebx", disp=0, idx=5, op="mov")])
    args = mk_args(memwrite_specs=[{"src":"ecx","base":"*"}], avoid_memref="ebx")
    from ropfilter.filters import gadget_matches
    assert gadget_matches(g, args) is True

def test_arith_mem_dst_match_then_avoid_star_exempts_that_arith():
    ar = {"op":"add", "dst_mem":{"base":"esi","disp":4,"abs":None}, "src":"eax", "idx":7}
    g = mk_gadget(arith=[ar])
    args = mk_args(arith=["op=add,dst_base=esi"], avoid_memref="*")
    from ropfilter.filters import gadget_matches
    assert gadget_matches(g, args) is True

def test_dispatch_mem_blocked_if_not_matched():
    disp = type("D", (), {"kind":"call","target":"mem","reg":"eax","absolute":None,"idx":3})
    g = mk_gadget(dispatch=[disp])
    args = mk_args(avoid_memref="*")  # no positive filter matched this dispatch
    from ropfilter.filters import gadget_matches
    assert gadget_matches(g, args) is False
