import pytest
from types import SimpleNamespace
from ropfilter.tests.conftest import MemOp, mk_args, mk_gadget
from ropfilter.filters import gadget_matches

# ---------- strict-mem debug print & absolute refs interplay ----------

def test_strict_mem_debug_message_path_is_executed(capsys):
    g = mk_gadget(memreads=[MemOp(dst="eax", absolute=0x401000, op="mov")])
    args = mk_args(strict_mem=True, debug=True)  # hit the debug print
    assert not gadget_matches(g, args)
    out = capsys.readouterr().out
    assert "strict-mem" in out.lower()

# ---------- _get_idx / _coerce_idx fallbacks (no idx recorded) ----------

def test_memread_no_idx_falls_back_to_enumeration_index():
    # idx=None should still be recorded/compared (fallback path)
    g = mk_gadget(memreads=[MemOp(dst="eax", base="esi", disp=4, op="mov", idx=None)])
    # match first; avoid * must skip the matching instruction, and since only one memref exists the gadget passes
    args = mk_args(memread_specs=[{"dst":"eax","base":"esi","disp":"4"}], avoid_memref="*")
    assert gadget_matches(g, args)

def test_reg2reg_no_position_array_fallback_and_stability_not_later_when_same_index():
    # Make reg2reg_pos short/missing and simulate "same position" (not later)
    g = mk_gadget(
        reg2reg=[("ecx","eax","mov"), ("ecx","eax","mov")],
        reg2reg_pos=[1],  # second one missing -> fallback
    )
    args = mk_args(reg2reg_specs=[("ecx","eax")], stable_dst=True)
    assert gadget_matches(g, args)  # same source → allowed

# ---------- avoid-memref: modes set/only + absolute behavior ----------

def test_avoid_memref_set_blocks_listed_bases_only():
    g1 = mk_gadget(memreads=[MemOp(dst="eax", base="ebx", disp=0, op="mov"),MemOp(dst="eax", base="edx", disp=0, op="mov")])
    g2 = mk_gadget(memreads=[MemOp(dst="eax", base="esi", disp=0, op="mov")])
    # set-mode 'ebx' blocks ebx but not esi
    assert not gadget_matches(g1, mk_args(memread_specs=[{"dst":"eax"}], avoid_memref="edx"))
    assert gadget_matches(g2, mk_args(memread_specs=[{"dst":"eax"}], avoid_memref="ebx"))

def test_avoid_memref_only_allows_listed_bases_blocks_others_and_absolute():
    # absolute read should be blocked in 'only' mode (base=None)
    g_abs = mk_gadget(memreads=[MemOp(dst="eax", absolute=0x402000, op="mov")])
    # base=esi allowed, base=ecx blocked
    g_ok  = mk_gadget(memreads=[MemOp(dst="eax", base="esi", disp=0, op="mov"),MemOp(dst="eax", base="ebx", disp=0, op="mov")])
    g_bad = mk_gadget(memreads=[MemOp(dst="ebx", base="ecx", disp=0, op="mov")])
    args = mk_args(memread_specs=[{"dst":"eax"}], strict_mem=True, avoid_memref="!esi|ebx")
    assert not gadget_matches(g_abs, args)  # absolute treated as blocked
    assert gadget_matches(g_ok, args)       # allowed base
    assert not gadget_matches(g_bad, args)  # non-listed base

def test_avoid_memref_star_override_only_when_explicit_base_is_named():
    # '*' would block memref unless base explicitly requested by another filter
    g = mk_gadget(memreads=[MemOp(dst="ecx", base="esi", disp=0, op="mov")])
    # Not explicit -> blocked
    assert not gadget_matches(g, mk_args(memread_specs=[{"dst":"eax"}], avoid_memref="*"))
    # Explicit base=esi -> allowed
    assert gadget_matches(g, mk_args(memread_specs=[{"dst":"ecx","base":"esi"}], avoid_memref="*"))

# ---------- avoid-memref over arithmetic memory operands ----------

def test_avoid_memref_applies_to_arith_src_mem_and_dst_mem_except_matched_one():
    a1 = {"op":"add","dst_mem":{"base":"esi","disp":4,"abs":None}, "src":"eax", "idx":5}
    a2 = {"op":"sub","dst":"ecx","src_mem":{"base":"edi","disp":8,"abs":None}, "idx":6}
    # Match a1 by dst_base=esi, then avoid '*' should block a2 (another memref)
    g = mk_gadget(arith=[a1, a2])
    args = mk_args(arith=["op=add,dst_base=esi"], avoid_memref="*")
    assert not gadget_matches(g, args)

# ---------- arithmetic displacement comparators (src/dst full fall-through) ----------

def test_arith_dst_disp_full_matrix_including_negatives():
    a = {"op":"add","dst_mem":{"base":"ebx","disp":4,"abs":None}, "src":"eax", "idx":2}
    g = mk_gadget(arith=[a])
    ok = [
        mk_args(arith=["op=add,dst_base=ebx,dst_disp=4"]),
        mk_args(arith=["op=add,dst_base=ebx,dst_disp>3"]),
        mk_args(arith=["op=add,dst_base=ebx,dst_disp>=4"]),
        mk_args(arith=["op=add,dst_base=ebx,dst_disp<5"]),
        mk_args(arith=["op=add,dst_base=ebx,dst_disp<=4"]),
    ]
    bad = [
        mk_args(arith=["op=add,dst_base=ebx,dst_disp>4"]),
        mk_args(arith=["op=add,dst_base=ebx,dst_disp<4"]),
    ]
    for aok in ok:
        assert gadget_matches(g, aok)
    for abad in bad:
        assert not gadget_matches(g, abad)

def test_arith_src_disp_full_matrix_including_negatives():
    a = {"op":"sub","dst":"ecx","src_mem":{"base":"esi","disp":7,"abs":None}, "idx":3}
    g = mk_gadget(arith=[a])
    ok = [
        mk_args(arith=["op=sub,src_base=esi,src_disp=7"]),
        mk_args(arith=["op=sub,src_base=esi,src_disp>6"]),
        mk_args(arith=["op=sub,src_base=esi,src_disp>=7"]),
        mk_args(arith=["op=sub,src_base=esi,src_disp<8"]),
        mk_args(arith=["op=sub,src_base=esi,src_disp<=7"]),
    ]
    bad = [
        mk_args(arith=["op=sub,src_base=esi,src_disp>7"]),
        mk_args(arith=["op=sub,src_base=esi,src_disp<7"]),
    ]
    for aok in ok:
        assert gadget_matches(g, aok)
    for abad in bad:
        assert not gadget_matches(g, abad)

# ---------- stable-dst: "not later" equal-index and "missing pop_pos" paths ----------

def test_stable_dst_memread_not_later_when_same_index_equivalence():
    mr1 = MemOp(dst="eax", base="esi", disp=4, op="mov", idx=5)
    mr2 = MemOp(dst="eax", base="esi", disp=4, op="mov", idx=5)  # same idx => not later
    g = mk_gadget(memreads=[mr1, mr2])
    args = mk_args(memread_specs=[{"dst":"eax","base":"esi","disp":"4"}], stable_dst=True)
    assert gadget_matches(g, args)

def test_stable_dst_pop_missing_pop_pos_treated_as_not_later():
    a = {"op":"add","dst":"eax","src":"ecx","idx":1}
    # pops present but no pop_pos -> code should treat as not later
    g = mk_gadget(arith=[a], pops=["eax"], pop_pos=[])
    args = mk_args(arith=["op=add,dst=eax,src=ecx"], stable_dst=True)
    assert gadget_matches(g, args)

# ---------- dispatch + avoid-memref on mem-target dispatch ----------

def test_dispatch_mem_respected_by_avoid_memref_when_not_the_match():
    d_mem = SimpleNamespace(kind="call", target="mem", reg="ebx", absolute=None, idx=7)
    g = mk_gadget(dispatch=[d_mem])
    # No dispatch filter to match this instruction -> avoid '*' should block it
    assert not gadget_matches(g, mk_args(avoid_memref="*"))
    # But if we explicitly match the dispatch (call_mem), it should be exempt from avoid
    assert gadget_matches(g, mk_args(call_mem="ebx", avoid_memref="*"))
