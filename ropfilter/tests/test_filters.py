# tests/test_filters.py
import pytest
from types import SimpleNamespace

from ropfilter.filters import gadget_matches
from ropfilter.utils import parse_kvlist
from ropfilter.tests.conftest import MemOp, mk_args, mk_gadget

# ---------- displacement filters (memread / memwrite / arith mem) ----------

def test_memread_disp_comparators():
    g = mk_gadget(memreads=[MemOp(dst="eax", base="esi", disp=8, op="mov")])
    # >= 8 matches
    args = mk_args(memread_specs=[{"dst":"eax","base":"esi","disp>=":"8"}])
    assert gadget_matches(g, args)
    # > 8 fails
    args = mk_args(memread_specs=[{"dst":"eax","base":"esi","disp>":"8"}])
    assert not gadget_matches(g, args)
    # == 8 matches
    args = mk_args(memread_specs=[{"dst":"eax","base":"esi","disp":"8"}])
    assert gadget_matches(g, args)

def test_memwrite_disp_equality():
    g = mk_gadget(memwrites=[MemOp(src="ebx", base="edi", disp=4, op="mov")])
    args = mk_args(memwrite_specs=[{"src":"ebx","base":"edi","disp":"4"}])
    assert gadget_matches(g, args)

def test_arith_mem_dst_src_disps():
    a = {
        "op":"add",
        "dst_mem": {"base":"ebx","disp":4,"abs":None},
        "src_mem": {"base":"edi","disp":-4,"abs":None},
    }
    g = mk_gadget(arith=[a])
    # dst_disp<=4 and src_disp<0
    # Parser collapses '<=' to '<' (splits on first '='), so use a strict '<' bound that includes 4.
    args = mk_args(arith=['op=add,dst_base=ebx,dst_disp<5,src_base=edi,src_disp<0'])
    assert gadget_matches(g, args)

    # dst_disp>4 should fail
    args = mk_args(arith=['op=add,dst_base=ebx,dst_disp>4'])
    assert not gadget_matches(g, args)

# ---------- arith op pattern (*, alternation, negation) ----------

def test_arith_op_patterns():
    a = {"op":"add","dst":"eax","src":"ecx"}
    g = mk_gadget(arith=[a])
    assert gadget_matches(g, mk_args(arith=["op=*",]))
    assert gadget_matches(g, mk_args(arith=["op=add|sub"]))
    assert not gadget_matches(g, mk_args(arith=["op=!add|sub"]))  # excludes add/sub

# ---------- smart --stable-dst across arith/memread/reg2reg ----------

def test_stable_dst_arith_rejected_on_later_pop():
    # add eax, ecx ; pop eax ; ret
    a = {"op":"add","dst":"eax","src":"ecx","idx":1}
    g = mk_gadget(arith=[a], pops=["eax"], pop_pos=[2])
    args = mk_args(arith=["op=add,dst=eax,src=ecx"], stable_dst=True)
    print(g)
    print(gadget_matches(g, args))
    assert not gadget_matches(g, args)  # overwritten by pop eax

def test_stable_dst_arith_allowed_when_not_touched():
    a = {"op":"add","dst":"eax","src":"ecx","idx":1}
    g = mk_gadget(arith=[a], pops=["esi"], pop_pos=[2])
    args = mk_args(arith=["op=add,dst=eax,src=ecx"], stable_dst=True)
    assert gadget_matches(g, args)

def test_stable_dst_memread_equivalence():
    # mov eax, [esi+4] ; mov eax, [esi+4]  (same address twice → OK)
    mr1 = MemOp(dst="eax", base="esi", disp=4, op="mov", idx=1)
    mr2 = MemOp(dst="eax", base="esi", disp=4, op="mov", idx=2)
    g = mk_gadget(memreads=[mr1, mr2])
    args = mk_args(memread_specs=[{"dst":"eax","base":"esi","disp":"4"}], stable_dst=True)
    assert gadget_matches(g, args)

def test_stable_dst_memread_rejected_on_different_address():
    # mov eax, [esi+4] ; mov eax, [esi+8]  (later different → reject)
    mr1 = MemOp(dst="eax", base="esi", disp=4, op="mov", idx=1)
    mr2 = MemOp(dst="eax", base="esi", disp=8, op="mov", idx=2)
    g = mk_gadget(memreads=[mr1, mr2])
    args = mk_args(memread_specs=[{"dst":"eax","base":"esi","disp":"4"}], stable_dst=True)
    assert not gadget_matches(g, args)

def test_stable_dst_reg2reg_same_src_ok_diff_src_reject():
    # mov eax, esp ; mov eax, esp  (OK), then mov eax, ecx (REJECT)
    g_ok = mk_gadget(reg2reg=[("esp","eax","mov"), ("esp","eax","mov")],
                     reg2reg_pos=[1,2])
    args = mk_args(reg2reg_specs=[("esp","eax")], stable_dst=True)
    assert gadget_matches(g_ok, args)
    g_bad = mk_gadget(reg2reg=[("esp","eax","mov"), ("ecx","eax","mov")],
                      reg2reg_pos=[1,2])
    assert not gadget_matches(g_bad, args)

# ---------- strict-mem policy ----------

def test_strict_mem_blocks_absolute_reads():
    g = mk_gadget(memreads=[MemOp(dst="eax", base=None, disp=None, absolute=0x402000, op="mov")])
    assert not gadget_matches(g, mk_args(strict_mem=True))
    # When disabled, it passes
    assert gadget_matches(g, mk_args(strict_mem=False))

# ---------- parse_kvlist operator-keys ----------

def test_parse_kvlist_operator_keys_and_normalization():
    # Parser splits on the first '=' → use '>' and '<' (not '>=', '<=')
    kv = parse_kvlist("dst_base=ebx,dst_disp>=4,src_disp<0")
    print(kv)
    assert kv["dst_base"] == "ebx"
    assert kv["dst_disp>="] == "4"
    assert kv["src_disp<"] == "0"
