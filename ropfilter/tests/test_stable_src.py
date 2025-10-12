import pytest
from ropfilter.tests.conftest import MemOp, mk_args, mk_gadget
from ropfilter.filters import gadget_matches

# -------------- reg2reg: earlier overwrite of SRC should reject --------------

def test_stable_src2reg_rejects_when_src_overwritten_earlier_by_reg2reg():
    # Earlier: mov edx, ecx  (writes edx)
    # Match:   mov edx, eax  (src=eax)  -> no earlier write to eax => OK
    g_ok = mk_gadget(
        reg2reg=[("ecx","edx","mov"), ("eax","edx","mov")],
        reg2reg_pos=[1, 2]
    )
    assert mk_args
    assert mk_gadget
    assert gadget_matches(g_ok, mk_args(reg2reg_specs=[("eax","edx")], stable_src=True))

    # Earlier: mov eax, ecx  (writes eax)
    # Match:   mov eax, edx  (src=edx)  -> earlier write to edx? no. OK.
    g_ok2 = mk_gadget(
        reg2reg=[("ecx","eax","mov"), ("edx","eax","mov")],
        reg2reg_pos=[1, 2]
    )
    assert gadget_matches(g_ok2, mk_args(reg2reg_specs=[("edx","eax")], stable_src=True))

    # Earlier: pop ecx  (writes ecx)
    # Match:   mov ecx, eax  (src=eax) -> earlier write to eax? no. OK.
    g_ok3 = mk_gadget(
        pops=["ecx"], pop_pos=[1],
        reg2reg=[("eax","ecx","mov")], reg2reg_pos=[2],
    )
    assert gadget_matches(g_ok3, mk_args(reg2reg_specs=[("eax","ecx")], stable_src=True))

    # Earlier: pop eax  (writes eax)
    # Match:   mov edx, eax  (src=eax) -> earlier write to eax -> REJECT
    g_bad = mk_gadget(
        pops=["eax"], pop_pos=[1],
        reg2reg=[("eax","edx","mov")], reg2reg_pos=[2],
    )
    assert not gadget_matches(g_bad, mk_args(reg2reg_specs=[("eax","edx")], stable_src=True))


# -------------- memwrite: earlier overwrite of SRC should reject --------------

def test_stable_src_memwrite_rejects_when_src_overwritten_earlier():
    # Earlier: mov ecx, edx (writes ecx)
    # Match: mov [ebx], ecx  (src=ecx) -> REJECT (ecx overwritten earlier)
    g_bad = mk_gadget(
        reg2reg=[("edx","ecx","mov")], reg2reg_pos=[1],
        memwrites=[MemOp(src="ecx", base="ebx", disp=0, op="mov", idx=2)],
    )
    args = mk_args(memwrite_specs=[{"src":"ecx","base":"ebx"}], stable_src=True)
    from ropfilter.filters import gadget_matches
    assert not gadget_matches(g_bad, args)

    # Earlier: mov eax, edx  (writes eax), match uses src=ecx => OK
    g_ok = mk_gadget(
        reg2reg=[("edx","eax","mov")], reg2reg_pos=[1],
        memwrites=[MemOp(src="ecx", base="ebx", disp=0, op="mov", idx=2)],
    )
    assert gadget_matches(g_ok, mk_args(memwrite_specs=[{"src":"ecx","base":"ebx"}], stable_src=True))


# -------------- arith: earlier overwrite of SRC should reject --------------

def test_stable_src_arith_rejects_when_src_overwritten_earlier_by_pop_and_reg2reg():
    # Earlier: pop edx (writes edx) and mov eax, edx (writes eax, irrelevant)
    # Match: add eax, edx (src=edx) -> REJECT due to earlier pop edx
    a = {"op":"add", "dst":"eax", "src":"edx", "idx":3}
    g_bad = mk_gadget(
        pops=["edx"], pop_pos=[1],
        reg2reg=[("edx","eax","mov")], reg2reg_pos=[2],
        arith=[a],
    )
    args = mk_args(arith=["op=add,dst=eax,src=edx"], stable_src=True)
    from ropfilter.filters import gadget_matches
    assert not gadget_matches(g_bad, args)

def test_stable_src_arith_ok_when_src_not_overwritten_earlier():
    # Earlier: pop ecx (doesn't touch edx)
    # Match: add eax, edx (src=edx) -> OK
    a = {"op":"add", "dst":"eax", "src":"edx", "idx":2}
    g_ok = mk_gadget(
        pops=["ecx"], pop_pos=[1],
        arith=[a],
    )
    args = mk_args(arith=["op=add,dst=eax,src=edx"], stable_src=True)
    from ropfilter.filters import gadget_matches
    assert gadget_matches(g_ok, args)
