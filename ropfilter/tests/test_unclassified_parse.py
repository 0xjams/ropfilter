import pytest
from ropfilter.classify import classify_gadget
from ropfilter.filters import gadget_matches
from ropfilter.tests.conftest import MemOp, mk_args, mk_gadget

class _Args:
    # minimal stub used in this test rig; adapt if your mk_args exists
    def __init__(self, arith_specs=None, avoid_memref=None, stable_dst=False):
        self.arith_specs = arith_specs or []
        self.avoid_memref = avoid_memref
        self.stable_dst = stable_dst

def test_avoid_memref_blocks_due_to_unclassified_mem():
    g = classify_gadget(0x710000, [
        "bswap eax",                 # match target
        "cmp dword ptr [eax], ecx",  # unclassified with mem
        "ret",
    ])
    args = mk_args(arith=["op=bswap,dst=eax"], avoid_memref="*")
    assert gadget_matches(g, args) is False

def test_stability_detects_later_unclassified_dst_write():
    g = classify_gadget(0x710001, [
        "add eax, ecx",
        "bswap eax",  # later write to eax (unclassified)
    ])
    args = mk_args(arith=["op=add,dst=eax,src=ecx"], stable_dst=True)
    assert gadget_matches(g, args) is False

from ropfilter.utils import canon_reg, set_exact_reg_mode

def test_canon_reg_legacy_maps_and_accepts_vec():
    set_exact_reg_mode(False)
    assert canon_reg("al") == "eax"
    assert canon_reg("xmm3") == "xmm3"
    assert canon_reg("mm7") == "mm7"
    assert canon_reg("st2") == "st2"
    assert canon_reg("bogus") is None

def test_canon_reg_exact_only_known():
    set_exact_reg_mode(True)
    assert canon_reg("eax") == "eax"
    assert canon_reg("al") == "al"
    assert canon_reg("xmm2") == "xmm2"
    assert canon_reg("mm0") == "mm0"
    assert canon_reg("st5") == "st5"
    print(canon_reg("notareg"))
    assert canon_reg("notareg") is None
