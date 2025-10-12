# ropfilter/tests/test_classify_more.py
import pytest
from ropfilter.classify import classify_gadget
from ropfilter.models import Gadget


def test_movbe_and_movsxd_and_movzx_movsx_are_classified():
    g = classify_gadget(0x401000, [
        "movbe eax, dword ptr [esi+4]",
        "movbe dword ptr [edi+8], ebx",
        "movsxd ecx, qword ptr [eax+0x10]",
        "movzx edx, byte ptr [ebx]",
        "movsx edi, word ptr [ecx+2]",
    ])
    # memreads / memwrites must be populated accordingly
    print(g.memreads)
    assert any(m.op in ("mov") for m in g.memreads)

    print(g.memwrites)
    assert any(m.op == "mov" for m in g.memwrites)


def test_cmov_memsrc_and_cmov_regsrc_and_xchg_mem_variants():
    g = classify_gadget(0x401100, [
        "cmovz eax, dword ptr [esi+8]",
        "cmovnz ebx, ecx",
        "xchg dword ptr [edi+4], edx",
        "xchg eax, dword ptr [ebx+0x10]",
        "xchg ecx, edx",
    ])
    # cmov memsrc should produce memread to eax and clobber eax
    assert any(m.dst == "eax" and m.base == "esi" and m.disp == 8 for m in g.memreads)
    assert "eax" in g.clobbers
    # cmov regsrc creates reg2reg
    assert any(s == "ecx" and d == "ebx" for (s, d, _) in g.reg2reg)
    # xchg mem<->reg yields both a memread and memwrite for that base
    assert any(m.base == "edi" for m in g.memreads) and any(m.base == "edi" for m in g.memwrites)
    assert any(m.base == "ebx" for m in g.memreads) and any(m.base == "ebx" for m in g.memwrites)
    # xchg reg,reg appends two reg2reg pairs
    assert any(s == "ecx" and d == "edx" for (s, d, _) in g.reg2reg)
    assert any(s == "edx" and d == "ecx" for (s, d, _) in g.reg2reg)


def test_lea_creates_reg2reg_and_arith_record():
    g = classify_gadget(0x401200, [
        "lea eax, [ebx+0x20]"
    ])
    # reg2reg produced (base -> dst) only when base exists and not absolute
    assert any(s == "ebx" and d == "eax" and k == "lea" for (s, d, k) in g.reg2reg)
    # arith record for lea exists and carries mem fields
    assert any(a.get("op") == "lea" and a.get("base") == "ebx" and a.get("dst") == "eax" for a in g.arith)


def test_arith_memdst_and_memsrcc_and_incdec_and_neg():
    g = classify_gadget(0x401300, [
        "add dword ptr [esi+4], eax",
        "sub ecx, dword ptr [edi+8]",
        "inc eax",
        "dec ebx",
        "neg ecx",
        "imul edx, eax, 5",
        "xadd eax, ebx",
    ])
    # memdst and memsrc should create arith dicts with dst_mem/src_mem
    print(g.arith)
    assert any(a.get("dst_mem", {}).get("base") == "esi" and a.get("src") == "eax" for a in g.arith)
    assert any(a.get("src_mem", {}).get("base") == "edi" and a.get("dst") == "ecx" for a in g.arith)
    # inc/dec/neg recorded as arith with immediate semantics
    assert any(a.get("op") == "inc" and a.get("dst") == "eax" for a in g.arith)
    assert any(a.get("op") == "dec" and a.get("dst") == "ebx" for a in g.arith)
    assert any(a.get("op") == "neg" and (a.get("dst") == "ecx" or a.get("src") == "ecx") for a in g.arith)
    # imul (3-operand) and xadd presence
    assert any(a.get("op") == "imul" for a in g.arith)
    assert any(a.get("op") == "xadd" for a in g.arith)


def test_dispatch_variants_and_pivot_synthesis():
    g = classify_gadget(0x401400, [
        "call eax",                 # reg dispatch
        "jmp dword ptr [ebx+0x10]", # mem dispatch
        "call 0x402000",            # abs dispatch
        "add esp, 0x20",            # pivot
        "sub esp, 0x10",            # pivot
        "pop esp",                  # pivot
        "leave",                    # pivot
        "mov esp, [esi]",           # pivot via memread -> dst=esp
        "push eax", "pop ecx",      # ensures push-pop pairing path exercised
        "ret",                      # end
    ])

    # dispatch kinds captured
    assert any(d.kind == "call" and d.target == "reg" for d in g.dispatch)
    assert any(d.kind == "jmp" and d.target == "mem" for d in g.dispatch)
    assert any(d.kind == "call" and d.target == "abs" for d in g.dispatch)

    # pivots should be synthesized from add/sub, pop esp, leave, and memread->esp
    assert g.pivot and any(p.kind in ("add","sub","pop","leave","mov") for p in g.pivot)

    # push/pop pairing should produce pop_pos and clobbers updated
    assert g.pop_pos and isinstance(g.pop_pos[0], int)
    assert "ecx" in g.clobbers


def test_mov_family_memread_memwrite_movzx_movsx_basic():
    g = classify_gadget(0x401500, [
        "mov eax, dword ptr [esi+4]",
        "mov dword ptr [edi+8], ebx",
        "movzx ecx, byte ptr [ebx]",
        "movsx edx, word ptr [ecx+2]",
    ])
    assert any(m.dst == "eax" and m.base == "esi" and m.disp == 4 for m in g.memreads)
    assert any(m.src == "ebx" and m.base == "edi" and m.disp == 8 for m in g.memwrites)
    assert any(m.dst == "ecx" and m.base == "ebx" for m in g.memreads)
    assert any(m.dst == "edx" and m.base == "ecx" and m.disp == 2 for m in g.memreads)


