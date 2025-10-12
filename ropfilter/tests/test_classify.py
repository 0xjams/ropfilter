# tests/test_classify.py
# Covers: movbe/movsxd/cmovcc, xchg [mem], push/pop [mem] pairing,
# xadd (mem/reg & reg/reg), legacy mov reg/reg & mov reg,imm,
# and dispatch targets (mem/reg/abs).
import pytest

from ropfilter.classify import classify_gadget


# ---------- helpers ----------
def cg(instrs):
    """Shorthand to classify a synthetic gadget."""
    return classify_gadget(0x1000, instrs)

def has_memread(g, *, dst=None, base=None, disp=None, absolute=None):
    for m in g.memreads:
        if m.disp==None:
            m.disp = 0
        if m.base==None:
            m.base = 0
        if (dst is None or m.dst == dst) and \
           (base is None or m.base == base) and \
           (disp is None or m.disp == disp) and \
           (absolute is None or m.absolute == absolute):
            return True
    return False

def has_memwrite(g, *, src=None, base=None, disp=None, absolute=None):
    for m in g.memwrites:
        if m.disp==None:
            m.disp = 0
        if m.base==None:
            m.base = 0
        if (src is None or m.src == src) and \
           (base is None or m.base == base) and \
           (disp is None or m.disp == disp) and \
           (absolute is None or m.absolute == absolute):
            return True
    return False

def reg2reg_in(g, src, dst, op=None):
    for s, d, o in g.reg2reg:
        if s == src and d == dst and (op is None or o == op):
            return True
    return False

def arith_in(g, **expect):
    """Loose matcher for an arith entry."""
    for e in g.arith:
        ok = True
        for k, v in expect.items():
            if k not in e:
                ok = False; break
            if isinstance(v, dict):
                # nested dict (dst_mem/src_mem)
                for kk, vv in v.items():
                    if e[k].get(kk) != vv:
                        ok = False; break
                if not ok: break
            else:
                if e[k] != v:
                    ok = False; break
        if ok:
            return True
    return False

def dispatch_in(g, *, kind, target, reg=None, absolute=None):
    for d in g.dispatch:
        if d.kind == kind and d.target == target:
            if target == "mem":
                if reg is None or d.reg == reg:
                    return True
            elif target == "reg":
                if reg is None or d.reg == reg:
                    return True
            elif target == "abs":
                if absolute is None or d.absolute == absolute:
                    return True
    return False


# ---------- tests ----------

def test_movbe_movsxd_cmovcc_variants():
    g = cg([
        "movbe eax, [ebx+4]",
        "movbe [ecx], edx",
        "cmovz edi, dword ptr [esi]",
        "cmovnz ecx, edx",
    ])
    print(g)
    assert has_memread(g, dst="eax", base="ebx", disp=4)
    assert has_memwrite(g, src="edx", base="ecx", disp=0)
    assert has_memread(g, dst="edi", base="esi", disp=0)
    assert reg2reg_in(g, "edx", "ecx", op="mov")


def test_xchg_mem_reg_emits_read_and_write_and_clobbers():
    g = cg(["xchg dword ptr [ebx+8], eax"])
    assert has_memread(g, dst="eax", base="ebx", disp=8)
    assert has_memwrite(g, src="eax", base="ebx", disp=8)
    assert "eax" in g.clobbers


def test_push_mem_pop_reg_upgrades_memread_dst_and_clobbers():
    g = cg([
        "push dword ptr [ebx+4]",
        "pop edi",
    ])
    # upgraded to dst=edi (not 'stack')
    assert has_memread(g, dst="edi", base="ebx", disp=4)
    assert "edi" in g.clobbers


def test_push_reg_pop_mem_pairs_into_memwrite():
    g = cg([
        "push eax",
        "pop [ecx+8]",
    ])
    assert has_memwrite(g, src="eax", base="ecx", disp=8)


def test_push_mem_pop_mem_is_stack_med_copy():
    g = cg([
        "push [ebx+4]",
        "pop [ecx+8]",
    ])
    assert has_memread(g, dst="stack", base="ebx", disp=4)
    assert has_memwrite(g, src="stack", base="ecx", disp=8)


def test_xadd_mem_reg_and_reg_reg():
    g = cg([
        "xadd dword ptr [eax+4], ecx",
        "xadd edx, ecx",
    ])
    assert arith_in(g, op="xadd", dst_mem={"base": "eax", "disp": 4, "abs": None}, src="ecx")
    assert arith_in(g, op="xadd", dst="edx", src="ecx")
    assert "edx" in g.clobbers and "ecx" in g.clobbers


def test_mov_reg_reg_and_mov_imm():
    g = cg([
        "mov eax, ebx",
        "mov ecx, 0x10",
    ])
    assert reg2reg_in(g, "ebx", "eax", op="mov")
    assert arith_in(g, op="movimm", dst="ecx", imm=0x10)


def test_dispatch_targets_mem_reg_abs():
    g = cg([
        "call dword ptr [eax+4]",
        "jmp ebx",
        "call 0x401000",
    ])
    # memory targets: Dispatch(kind, "mem", reg=base)
    assert dispatch_in(g, kind="call", target="mem", reg="eax")
    assert dispatch_in(g, kind="jmp", target="reg", reg="ebx")
    assert dispatch_in(g, kind="call", target="abs", absolute=0x401000)
