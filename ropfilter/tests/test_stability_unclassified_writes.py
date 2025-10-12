import pytest
from ropfilter.tests.conftest import mk_args, mk_gadget

def test_stable_dst_rejects_on_unclassified_later_write():
    # Gadget: matched arith at idx=2 writing dst=eax, and then later an unclassified writer to eax at idx=3
    # We simulate the fallback classifier having recorded ('bswap eax' at idx 3) in unclassified_reg_writes.

    args = mk_args(arith=["op=add,dst=eax,src=ecx"], stable_dst=True)

    from ropfilter.classify import classify_gadget
    from ropfilter.filters import gadget_matches
    g = classify_gadget(0x500000, [
        "add eax,ebx",       
        "bswap al"   
    ])
    assert gadget_matches(g, args) is False  # later write to dst → reject

def test_stable_src_rejects_on_unclassified_earlier_write():
    # Gadget: earlier fallback writer to edx at idx=1 (e.g., 'setnz edx')
    # Match: arith 'add eax, edx' at idx=3 with --stable-src ⇒ reject (src overwritten earlier)
    a = {"op":"add", "dst":"eax", "src":"edx", "idx":3}
    g = mk_gadget(arith=[a])
    g.unclassified_reg_writes = [(1, "setnz", "edx", None)]
    args = mk_args(arith=["op=add,dst=eax,src=edx"], stable_src=True)
    from ropfilter.filters import gadget_matches

    assert gadget_matches(g, args) is False

def test_stable_src_ok_when_unclassified_writes_other_register():
    # Earlier fallback write to ecx (not src=edx). Should not affect stable-src for edx
    a = {"op":"add", "dst":"eax", "src":"edx", "idx":5}
    g = mk_gadget(arith=[a])
    g.unclassified_reg_writes = [(2, "bsr", "ecx", None)]
    args = mk_args(arith=["op=add,dst=eax,src=edx"], stable_src=True)
    from ropfilter.filters import gadget_matches
    assert gadget_matches(g, args) is True

def test_stable_dst_ok_when_unclassified_is_before_match():
    # Unclassified writer to eax at idx=1, match arith writes eax at idx=4 with stable-dst
    # Later overwrite? None. Earlier overwrite doesn't violate stable-dst (it checks 'later').
    a = {"op":"add", "dst":"eax", "src":"ecx", "idx":4}
    g = mk_gadget(arith=[a])
    g.unclassified_reg_writes = [(1, "bswap", "eax", None)]
    args = mk_args(arith=["op=add,dst=eax,src=ecx"], stable_dst=True)
    from ropfilter.filters import gadget_matches
    assert gadget_matches(g, args) is True
