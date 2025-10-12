# tests/test_classify_extended.py  (x86-only)
import pytest
from ropfilter.classify import classify_gadget

# ---------- helpers ----------
def cg(lines):
    return classify_gadget(0x1337, lines)

def _find(memops, **kw):
    for m in memops:
        ok = True
        for k, v in kw.items():
            if getattr(m, k, None) != v:
                ok = False; break
        if ok: return True
    return False

def has_memread(g, **kw):  return _find(g.memreads, **kw)
def has_memwrite(g, **kw): return _find(g.memwrites, **kw)

def reg2reg_in(g, src, dst, op=None):
    for s, d, o in g.reg2reg:
        if s == src and d == dst and (op is None or o == op):
            return True
    return False

def arith_has(g, **expect):
    for e in g.arith:
        ok = True
        for k, v in expect.items():
            if k not in e: ok = False; break
            if isinstance(v, dict):
                for kk, vv in v.items():
                    if e[k].get(kk) != vv: ok = False; break
                if not ok: break
            else:
                if e[k] != v: ok = False; break
        if ok: return True
    return False

def dispatch_has(g, *, kind, target, reg=None, absolute=None):
    for d in g.dispatch:
        if d.kind == kind and d.target == target:
            if target in ("reg","mem"):
                if reg is None or d.reg == reg: return True
            elif target == "abs":
                if absolute is None or d.absolute == absolute: return True
    return False


# ---------- MOV family (loads/stores / sizes / case) ----------
@pytest.mark.parametrize("msize", ["", "byte ptr ", "word ptr ", "dword ptr "])
def test_mov_load_sizes_and_case(msize):
    g = cg([f"MoV EAX, {msize}[EBX+4]"])
    assert has_memread(g, dst="eax", base="ebx", disp=4)

@pytest.mark.parametrize("msize", ["", "dword ptr "])
def test_mov_store_sizes(msize):
    g = cg([f"mov {msize}[ecx+8], edx"])
    assert has_memwrite(g, src="edx", base="ecx", disp=8)

@pytest.mark.parametrize("line, dst", [
    ("movzx eax, byte ptr [ecx]", "eax"),
    ("movsx edx, word ptr [esi+2]", "edx"),
])
def test_movzx_movsx_mem_loads(line, dst):
    g = cg([line])
    assert len(g.memreads) == 1
    assert g.memreads[0].dst == dst

def test_movbe_load_and_store():
    g = cg([
        "movbe eax, [ebx+4]",
        "movbe [ecx+0x20], edx",
    ])
    assert has_memread(g, dst="eax", base="ebx", disp=4)
    assert has_memwrite(g, src="edx", base="ecx", disp=0x20)

def test_mov_reg_reg_and_mov_imm():
    g = cg([
        "mov eax, ebx",
        "mov ecx, 0x10",
    ])
    assert reg2reg_in(g, "ebx", "eax", op="mov")
    assert arith_has(g, op="movimm", dst="ecx", imm=0x10)


# ---------- CMOVcc (mem-size aware, reg-src) ----------
@pytest.mark.parametrize("suffix", ["z","nz","be","a","l","ge","po","pe"])
@pytest.mark.parametrize("msize", ["", "dword ptr "])
def test_cmovcc_mem_and_reg_sources(suffix, msize):
    g = cg([
        f"cmov{suffix} edi, {msize}[esi]",
        f"cmov{suffix} ecx, edx",
    ])
    assert has_memread(g, dst="edi", base="esi", disp=0)
    assert reg2reg_in(g, "edx", "ecx")


# ---------- XCHG (reg<->mem & reg<->reg) ----------
def test_xchg_mem_reg_both_orders():
    g = cg([
        "xchg dword ptr [ebx+8], eax",
        "xchg edx, dword ptr [ecx+16]",
        "xchg esi, edi",
    ])
    # first
    assert has_memread(g, dst="eax", base="ebx", disp=8)
    assert has_memwrite(g, src="eax", base="ebx", disp=8)
    # second
    assert has_memread(g, dst="edx", base="ecx", disp=16)
    assert has_memwrite(g, src="edx", base="ecx", disp=16)
    # reg-reg yields two directions
    assert reg2reg_in(g, "esi", "edi", op="xchg")
    assert reg2reg_in(g, "edi", "esi", op="xchg")


# ---------- PUSH/POP (pair-aware) ----------
def test_push_mem_pop_reg_upgrades_dst_and_clobbers():
    g = cg(["push dword ptr [ebx+4]", "pop edi"])
    assert has_memread(g, dst="edi", base="ebx", disp=4)
    assert "edi" in g.clobbers

def test_push_reg_pop_mem_pairs_into_write():
    g = cg(["push eax", "pop [ecx+8]"])
    assert has_memwrite(g, src="eax", base="ecx", disp=8)

def test_push_mem_pop_mem_stack_mediated_copy():
    g = cg(["push [ebx+4]", "pop [ecx+8]"])
    assert has_memread(g, dst="stack", base="ebx", disp=4)
    assert has_memwrite(g, src="stack", base="ecx", disp=8)

def test_multiple_pushes_and_pops_interleave():
    g = cg([
        "push [ebx]",     # mem -> stack
        "push ecx",       # reg -> stack
        "pop [edi+4]",    # pairs with ecx
        "pop eax",        # upgrades earlier memread to eax
    ])
    assert has_memwrite(g, src="ecx", base="edi", disp=4)
    assert has_memread(g, dst="eax", base="ebx", disp=0)


# ---------- ARITH / LOGIC (mem dst/src, reg/reg, XADD) ----------
def test_arith_memdst_reg_and_imm_and_abs():
    g = cg([
        "add dword ptr [ecx+8], edx",       # RMW via reg
        "and dword ptr [0x401000], 0xFF",   # RMW via imm on absolute
    ])
    assert arith_has(g, op="add", dst_mem={"base":"ecx","disp":8,"abs":None}, src="edx")
    assert arith_has(g, op="and", dst_mem={"base":None,"disp":0,"abs":0x401000}, imm=0xFF)

def test_arith_memsrc_load_and_regreg_and_unary():
    g = cg([
        "add eax, dword ptr [ecx+8]",   # mem src load
        "imul edx, dword ptr [esi+0x10]",
        "neg dword ptr [ebx+4]",
        "inc edi",
        "dec esi",
    ])
    print(g)
    assert has_memread(g, dst="eax", base="ecx", disp=8)
    assert arith_has(g, op="imul", dst="edx", src_mem={"base":"esi","disp":0x10,"abs":None})
    assert arith_has(g, op="neg",  dst_mem={"base":"ebx","disp":4,"abs":None})
    assert arith_has(g, op="inc",  dst="edi", imm=1)
    assert arith_has(g, op="dec",  dst="esi", imm=-1)

def test_xadd_valid_and_invalid_forms():
    g = cg([
        "xadd dword ptr [eax+4], ecx",  # valid (RMW)
        "xadd edx, ecx",                # valid reg,reg
        "xadd eax, 1",                  # invalid -> ignored
        "xadd eax, [ecx]",              # invalid -> ignored
    ])
    assert arith_has(g, op="xadd", dst_mem={"base":"eax","disp":4,"abs":None}, src="ecx")
    assert arith_has(g, op="xadd", dst="edx", src="ecx")
    cnt = sum(1 for e in g.arith if e.get("op") == "xadd")
    assert cnt == 2


# ---------- LEA ----------
def test_lea_base_and_absolute():
    g = cg([
        "lea eax, [ebx+8]",
        "lea ecx, [0x402000]",
    ])
    assert reg2reg_in(g, "ebx", "eax", op="lea")
    assert arith_has(g, op="lea", dst="eax", base="ebx", disp=8, abs=None)
    assert not reg2reg_in(g, "0x402000", "ecx", op="lea")
    print(g)
    assert arith_has(g, op="lea", dst="ecx", base=None, disp=0, abs=0x402000)


# ---------- Flow: RET / CALL / JMP ----------
def test_ret_and_retn_imm():
    g1 = cg(["ret"])
    assert g1.ret_imm == 0 and g1.stack_delta == 4
    g2 = cg(["retn 0x10"])
    assert g2.ret_imm == 0x10 and g2.stack_delta == 4 + 0x10

@pytest.mark.parametrize("line, kind, target, reg, absolute", [
    ("call dword ptr [eax+4]", "call", "mem", "eax", None),
    ("jmp ebx",                 "jmp",  "reg", "ebx", None),
    ("call 0x401000",           "call", "abs", None,  0x401000),
    ("jmp dword ptr [0x402000]","jmp",  "mem", None,  None),  # indirect via absolute (no base reg)
])
def test_dispatch_variants(line, kind, target, reg, absolute):
    g = cg([line])
    assert dispatch_has(g, kind=kind, target=target, reg=reg, absolute=absolute)


# ---------- Spacing robustness + pivots ----------
def test_weird_spacing_and_case_and_pivots():
    g = cg([
        "  MOV   eax ,  [ ebx + 0xC ]  ",
        "xChG  [ecx] ,  edx",
        "PoP  [  edi + 4 ]",
        "PUSH    DWORD PTR   [esi]",
        "CMOVz  EDI, DWORD PTR [ESI]",
        "xchg esp, eax",
        "add esp, 0x20",
    ])
    assert has_memread(g, dst="eax", base="ebx", disp=0xC)
    assert has_memread(g, dst="edx", base="ecx", disp=0)
    assert has_memwrite(g, src="stack", base="edi", disp=4)
    assert has_memread(g, dst="stack", base="esi", disp=0)   # not immediately popped into a reg
    assert has_memread(g, dst="edi", base="esi", disp=0)     # cmovz mem-read
    kinds = [p.kind for p in g.pivot]
    assert "xchg" in kinds or "mov" in kinds
    assert "add" in kinds


def test_lea_with_memsize():
    g = classify_gadget(0x1337, ["lea eax, dword ptr [ebx+8]"])
    # Should behave exactly like the no-memsize form
    assert any(e for e in g.arith if e.get("op") == "lea" and e.get("dst") == "eax"
               and e.get("base") == "ebx" and e.get("disp") == 8 and e.get("abs") is None)
    # Optional: you keep emitting reg2reg(base->dst) when base is a register
    assert any((s, d, o) == ("ebx", "eax", "lea") for (s, d, o) in g.reg2reg)
