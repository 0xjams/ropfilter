# tests/test_chain_ranking_and_stability.py
# Run with:  pytest -q
#
# This suite covers:
#  - Stability checks (_earlier_overwrite_exists / _later_overwrite_is_different) treating partial regs
#    as same physical register family (eax=ax=al=ah), including unclassified_reg_writes.
#  - Chain return enforcement (gadgets without any ret/retn are excluded).
#  - LEA-aware ranking for reg2reg hops by correlating reg2reg[kind="lea"] with arith(op="lea") to use disp.
#  - memread/memwrite displacement ranking preference when selecting chain hops.
#  - Per-hop candidate sorting stability (deterministic best-first).
#
# Notes:
#  - We avoid relying on repo-internal scoring implementations by monkeypatching
#    chain.gadget_matches + chain.memread_disp_rank/memwrite_disp_rank/ret_rank_of
#    to make tests self-contained and focused on selection logic.
#  - We use SimpleNamespace to synthesize "gadgets" with only the attributes the code touches.

import types
from types import SimpleNamespace as NS

import pytest

# ---- Imports under test
import ropfilter.filters as filters
import ropfilter.chain as chain


# ------------------------
# Test scaffolding helpers
# ------------------------

def G(**kw):
    """
    Build a minimal gadget-like object (SimpleNamespace) with fields used by chain/filters.
    Defaults for all sequences are empty; unspecified scalars are None.
    """
    g = NS()
    # Common scalar attributes
    g.address = kw.get("address", 0)
    g.instr_count = kw.get("instr_count", 1)
    g.ret_imm = kw.get("ret_imm", None)  # None => no return; 0 => ret; >0 => retn imm
    # Stability-related collections
    g.unclassified_reg_writes = kw.get("unclassified_reg_writes", [])
    g.pops = kw.get("pops", [])
    g.pop_pos = kw.get("pop_pos", [])
    # Core classifier outputs used by chain
    g.reg2reg = kw.get("reg2reg", [])
    g.reg2reg_pos = kw.get("reg2reg_pos", [])
    g.arith = kw.get("arith", [])
    g.memreads = kw.get("memreads", [])
    g.memreads_pos = kw.get("memreads_pos", [])
    g.memwrites = kw.get("memwrites", [])
    g.memwrites_pos = kw.get("memwrites_pos", [])
    g.clobbers = kw.get("clobbers", [])
    return g


def MR(**kw):
    """
    MemRead-like record (dict) with dst, base, disp, abs (absolute), op, idx.
    """
    d = dict(dst=kw.get("dst"), base=kw.get("base"), disp=kw.get("disp", 0),
             absolute=kw.get("abs"), op=kw.get("op"), idx=kw.get("idx", 0))
    return types.SimpleNamespace(**d)


def MW(**kw):
    """
    MemWrite-like record (dict) with base, src, disp, abs (absolute), op, idx.
    Note: memwrite records usually do not carry 'dst'; the write target is memory at [base+disp].
    """
    d = dict(base=kw.get("base"), src=kw.get("src"), disp=kw.get("disp", 0),
             absolute=kw.get("abs"), op=kw.get("op"), idx=kw.get("idx", 0))
    return types.SimpleNamespace(**d)


# ------------------------
# Monkeypatches for ranking/policy to make outcomes deterministic
# ------------------------

@pytest.fixture(autouse=True)
def patch_chain_rankers_and_policy(monkeypatch):
    """
    Make ret/memread/memwrite rankers deterministic and policy permissive so
    tests exercise chain's selection logic, not external policy/weights.
    """

    # Always pass policy checks in gadget_matches for our synthetic gadgets
    monkeypatch.setattr(chain, "gadget_matches", lambda g, _args: True, raising=False)

    # ret_rank_of: 0 for clean ret (ret_imm==0), 1 for retn imm (>0), 2 (worst) for anything else.
    def _ret_rank_of(g):
        if g.ret_imm is None:
            return 2
        return 0 if g.ret_imm == 0 else 1
    monkeypatch.setattr(chain, "ret_rank_of", _ret_rank_of, raising=False)

    # memread_disp_rank: derive from the actual MR.disp at index j (if any); bucket like 0/<=8/<=32/<=128/else
    def _memread_disp_rank(g, j_or_list):
        # Some repo variants accept (g, j), others (g, candidates); normalize to index if possible
        j = 0
        if isinstance(j_or_list, int):
            j = j_or_list
        elif isinstance(j_or_list, (list, tuple)) and j_or_list:
            # we were passed a list of dicts; try to map to the first memread index
            j = 0
        disp = 0
        mrs = getattr(g, "memreads", []) or []
        if 0 <= j < len(mrs):
            disp = getattr(mrs[j], "disp", 0) or 0
        d = abs(int(disp))
        if d == 0: return 0
        if d <= 8: return 1
        if d <= 32: return 2
        if d <= 128: return 3
        return 4
    monkeypatch.setattr(chain, "memread_disp_rank", _memread_disp_rank, raising=False)

    # memwrite_disp_rank: same bucketing using MW.disp at index j
    def _memwrite_disp_rank(g, j_or_list):
        j = 0
        if isinstance(j_or_list, int):
            j = j_or_list
        elif isinstance(j_or_list, (list, tuple)) and j_or_list:
            j = 0
        disp = 0
        mws = getattr(g, "memwrites", []) or []
        if 0 <= j < len(mws):
            disp = getattr(mws[j], "disp", 0) or 0
        d = abs(int(disp))
        if d == 0: return 0
        if d <= 8: return 1
        if d <= 32: return 2
        if d <= 128: return 3
        return 4
    monkeypatch.setattr(chain, "memwrite_disp_rank", _memwrite_disp_rank, raising=False)

    # reg2reg LEA disp rank via arith lookup (same approach as production code)
    def _reg2reg_lea_disp_rank(g, j, S, D):
        try:
            _s, _d, kind = g.reg2reg[j]
        except Exception:
            return 0
        if kind != "lea":
            return 0
        # find the arith 'lea' matching (dst==D, base==S) nearest to reg2reg_pos[j]
        pos_list = getattr(g, "reg2reg_pos", []) or []
        anchor = pos_list[j] if j < len(pos_list) else None
        best = None
        for a in getattr(g, "arith", []) or []:
            if not isinstance(a, dict) and not isinstance(a, NS):
                continue
            if (getattr(a, "op", None) or a.get("op")) != "lea":
                continue
            dst = getattr(a, "dst", None) if isinstance(a, NS) else a.get("dst")
            base = getattr(a, "base", None) if isinstance(a, NS) else a.get("base")
            if chain.canon_reg(dst or "") != D or chain.canon_reg(base or "") != S:
                continue
            disp = getattr(a, "disp", 0) if isinstance(a, NS) else (a.get("disp", 0) or 0)
            ai = getattr(a, "idx", 0) if isinstance(a, NS) else a.get("idx", 0)
            delta = abs((ai or 0) - (anchor or 0))
            cand = (delta, abs(int(disp)))
            if best is None or cand < best:
                best = cand
        if best is None:
            return 0
        d = best[1]
        if d == 0: return 0
        if d <= 8: return 1
        if d <= 32: return 2
        if d <= 128: return 3
        return 4

    # make helper available on chain (the production code calls a similarly named helper)
    monkeypatch.setattr(chain, "_reg2reg_lea_disp_rank", _reg2reg_lea_disp_rank, raising=False)

    yield


# ------------------------
# Stability tests
# ------------------------

def test_same_phys_reg_family_equivalence():
    assert filters._same_phys_reg("eax", "al")
    assert filters._same_phys_reg("eax", "ah")
    assert filters._same_phys_reg("eax", "ax")
    assert filters._same_phys_reg("ecx", "ch")
    assert not filters._same_phys_reg("eax", "ecx")


def test_earlier_overwrite_detects_unclassified_partial():
    g = G(unclassified_reg_writes=[{'op':'add','dst':'al','src':'ebx','idx':1}])
    assert filters._earlier_overwrite_exists(g, upto_idx=5, reg="eax") is True


def test_earlier_overwrite_ignores_future_write():
    g = G(unclassified_reg_writes=[(7, "al")])
    assert filters._earlier_overwrite_exists(g, upto_idx=5, reg="eax") is False


def test_later_overwrite_is_different_memread_to_partial_reg():
    start_idx = 2
    dst = "eax"
    original_kind = "reg2reg"
    meta = {"src": "edx"}
    mr = MR(dst="al", base="ebx", disp=0x10, abs=None, op=None, idx=6)
    g = G(memreads=[mr])
    assert filters._later_overwrite_is_different(g, start_idx, dst, original_kind, meta) is True


def test_later_overwrite_equivalent_memread_same_address_and_op():
    start_idx = 1
    dst = "eax"
    original_kind = "memread"
    meta = {"abs": None, "base": "esi", "disp": 4, "op": None}
    mr_same = MR(dst="ax", base="esi", disp=4, abs=None, op=None, idx=5)
    g = G(memreads=[mr_same])
    assert filters._later_overwrite_is_different(g, start_idx, dst, original_kind, meta) is False


def test_later_overwrite_unclassified_write_counts():
    start_idx = 2
    dst = "eax"
    original_kind = "memread"
    meta = {"abs": 0x401000, "base": None, "disp": None, "op": None}
    g = G(unclassified_reg_writes=[{"idx": 6, "dst": "ah"}])

    assert filters._later_overwrite_is_different(g, start_idx, dst, original_kind, meta) is True


# ------------------------
# Chain-level tests
# ------------------------

def test_is_clean_ret_enforces_any_return():
    g_no = G(ret_imm=None)
    g_ret = G(ret_imm=0)
    g_retn = G(ret_imm=4)
    assert chain.is_clean_ret(g_no) is False
    assert chain.is_clean_ret(g_ret) is True
    assert chain.is_clean_ret(g_retn) is True


def test_build_transfer_edges_prefers_disp0_lea_over_disp40():
    # Build two reg2reg gadgets for ECX->EAX:
    #  - g0: LEA with disp=0 (but longer)
    #  - g1: LEA with disp=0x40 (shorter)
    # Ranking should pick disp=0 as better due to lea-disp rank before instr_count

    g0 = G(
        address=0x1000, instr_count=5, ret_imm=0,
        reg2reg=[("ecx", "eax", "lea")], reg2reg_pos=[10],
        arith=[dict(op="lea", dst="eax", base="ecx", disp=0, idx=10)]
    )
    g1 = G(
        address=0x0FFF, instr_count=1, ret_imm=0,
        reg2reg=[("ecx", "eax", "lea")], reg2reg_pos=[20],
        arith=[dict(op="lea", dst="eax", base="ecx", disp=0x40, idx=20)]
    )

    edges = chain.build_transfer_edges([g1, g0], args=NS())  # order in input shouldn't matter
    # Find the ECX source edges and ensure first candidate to EAX is g0
    e = edges.get("ecx", [])
    assert e, "No edges built for ECX"
    dst0, gadget0 = e[0]
    assert dst0 == "eax"
    assert gadget0.address == 0x1000  # disp 0 gadget chosen


def test_build_transfer_edges_excludes_non_returning_gadgets():
    g_nr = G(address=0x2000, instr_count=1, ret_imm=None,
             reg2reg=[("ecx", "eax", "lea")], reg2reg_pos=[2],
             arith=[dict(op="lea", dst="eax", base="ecx", disp=0, idx=2)])
    g_ok = G(address=0x2001, instr_count=2, ret_imm=0,
             reg2reg=[("ecx", "eax", "lea")], reg2reg_pos=[2],
             arith=[dict(op="lea", dst="eax", base="ecx", disp=0x10, idx=2)])
    edges = chain.build_transfer_edges([g_nr, g_ok], args=NS())
    e = edges.get("ecx", [])
    assert e and e[0][1].address == 0x2001
    # non-returning gadget should not appear
    assert all(g.address != 0x2000 for _, g in e)


def test_find_memread_chain_prefers_memread_with_smaller_disp_and_bridge_lea_disp():
    # We want a chain that ultimately moves ECX->EAX via:
    #  [memread]->T  and then T->EAX (reg2reg bridge)
    # Prepare two memreads into T=edx: disp=0 (longer), disp=0x40 (shorter) — pick disp 0.
    mr0 = MR(dst="edx", base="esi", disp=0, idx=1)
    mr1 = MR(dst="edx", base="esi", disp=0x40, idx=2)
    gr0 = G(address=0x3000, instr_count=5, ret_imm=0, memreads=[mr0], memreads_pos=[1])
    gr1 = G(address=0x3001, instr_count=1, ret_imm=0, memreads=[mr1], memreads_pos=[2])

    # Bridge reg2reg T=edx -> D=eax: two options, disp=0 is better than disp=0x80
    gbridge0 = G(address=0x3100, instr_count=4, ret_imm=0,
                 reg2reg=[("edx", "eax", "lea")], reg2reg_pos=[5],
                 arith=[dict(op="lea", dst="eax", base="edx", disp=0, idx=5)])
    gbridge1 = G(address=0x3101, instr_count=1, ret_imm=0,
                 reg2reg=[("edx", "eax", "lea")], reg2reg_pos=[6],
                 arith=[dict(op="lea", dst="eax", base="edx", disp=0x80, idx=6)])

    gadgets = [gr0, gr1, gbridge1, gbridge0]
    # We call find_memread_chain the same way chain.py calls it internally;
    # it expects some args object but we only use gadget_matches (already patched to True).
    chains = chain.find_memread_chain("eax", "esi", gadgets, NS())

    assert chains, "No memread chains produced"
    best = chains[0]
    # Ensure first hop chosen is gr0 (disp 0 memread), second hop is gbridge0 (disp 0 lea)
    assert best[0].address == 0x3000
    assert best[1].address == 0x3100


def test_find_memwrite_chain_prefers_incoming_reg2reg_with_smaller_lea_disp_and_memwrite_disp():
    # Target: write T to [B] with best memwrite (disp rank), and if S is fixed,
    # pick the best incoming reg2reg S->T using LEA disp ranking.

    # Memwrites of T=edx to [esi+disp]: choose disp=0 over disp=0x20
    mw0 = MW(base="esi", src="edx", disp=0, idx=3)
    mw1 = MW(base="esi", src="edx", disp=0x20, idx=4)
    gmw0 = G(address=0x4000, instr_count=5, ret_imm=0, memwrites=[mw0], memwrites_pos=[3])
    gmw1 = G(address=0x4001, instr_count=1, ret_imm=0, memwrites=[mw1], memwrites_pos=[4])

    # Incoming reg2reg from S=ecx to T=edx: choose LEA disp 0 over disp 0x100
    ginc0 = G(address=0x4100, instr_count=3, ret_imm=0,
              reg2reg=[("ecx", "edx", "lea")], reg2reg_pos=[9],
              arith=[dict(op="lea", dst="edx", base="ecx", disp=0, idx=9)])
    ginc1 = G(address=0x4101, instr_count=1, ret_imm=0,
              reg2reg=[("ecx", "edx", "lea")], reg2reg_pos=[10],
              arith=[dict(op="lea", dst="edx", base="ecx", disp=0x100, idx=10)])

    # Include a non-returning candidate to ensure it's ignored
    g_bad = G(address=0x4102, instr_count=1, ret_imm=None,
              reg2reg=[("ecx", "edx", "lea")], reg2reg_pos=[11],
              arith=[dict(op="lea", dst="edx", base="ecx", disp=0, idx=11)])

    gadgets = [gmw1, gmw0, ginc1, ginc0, g_bad]
    #find_memwrite_chain(src, base, gadgets: List[Gadget], args) -> List[List[Gadget]]:
    chains = chain.find_memwrite_chain("ecx", "esi", gadgets, NS())

    assert chains, "No memwrite chains produced"
    best = chains[0]
    # Expect first hop = best incoming reg2reg (disp 0), second hop = best memwrite (disp 0)
    assert best[0].address == 0x4100
    assert best[1].address == 0x4000


def test_build_transfer_edges_orders_multiple_targets_and_is_deterministic():
    # Build multiple edges from ECX to {EAX, EDX} and make sure per-hop sorting is stable
    g_eax_bad = G(address=0x5000, instr_count=1, ret_imm=0,
                  reg2reg=[("ecx", "eax", "lea")], reg2reg_pos=[1],
                  arith=[dict(op="lea", dst="eax", base="ecx", disp=0x80, idx=1)])
    g_eax_good = G(address=0x5001, instr_count=4, ret_imm=0,
                   reg2reg=[("ecx", "eax", "lea")], reg2reg_pos=[2],
                   arith=[dict(op="lea", dst="eax", base="ecx", disp=0, idx=2)])
    g_edx_good = G(address=0x5002, instr_count=2, ret_imm=0,
                   reg2reg=[("ecx", "edx", "lea")], reg2reg_pos=[3],
                   arith=[dict(op="lea", dst="edx", base="ecx", disp=0, idx=3)])
    edges = chain.build_transfer_edges([g_eax_bad, g_eax_good, g_edx_good], args=NS())
    # For ECX, ensure first edge to EAX picks g_eax_good (disp 0), and EDX edge exists
    e = edges.get("ecx", [])
    assert e
    # There should be two distinct targets in order of when we iterate (both kept), but
    # we verify the preferred gadget for EAX is the disp=0 one.
    eax_edges = [pair for pair in e if pair[0] == "eax"]
    assert eax_edges and eax_edges[0][1].address == 0x5001
    edx_edges = [pair for pair in e if pair[0] == "edx"]
    assert edx_edges and edx_edges[0][1].address == 0x5002
