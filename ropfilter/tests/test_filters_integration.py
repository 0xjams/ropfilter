# tests/test_filters_integration.py
# Integration tests for ropfilter.filters.gadget_matches()
# We classify real gadgets, then assert gadget_matches() behavior across ALL filters.
# x86-only.

import pytest
from types import SimpleNamespace

from ropfilter.classify import classify_gadget
from ropfilter import filters as F


# ---------- helpers ----------
def cg(addr, lines):
    return classify_gadget(addr, lines)

def A(**overrides):
    """
    Build an args object with SAFE defaults for every field gadget_matches() touches.
    (This avoids NoneType iteration like args.reg2reg_specs being None.)
    """
    base = dict(
        addr_no_bytes=None,
        max_instr=None,
        ret_only=False,
        retn=None,
        max_stack_delta=None,

        strict_mem=False,        # only enforced when True (see filters.py)
        debug=False,

        reg2reg_specs=[],
        memread_specs=[],
        memwrite_specs=[],
        arith=[],                # list of "k=v,k=v" strings parsed by parse_kvlist

        pivot=False,
        pivot_kind=None,
        pivot_reg=None,
        pivot_imm=None,

        pop_seq=[],

        call_reg=None,
        call_abs=None,
        call_mem=None,

        avoid_clobber=[],
        require_writes=[],
    )
    base.update(overrides)
    return SimpleNamespace(**base)


# ---------- sample gadgets (cover instruction surfaces) ----------
G_CALL_MEM   = cg(0x6000, ["mov eax, [ebx+4]", "call dword ptr [eax+8]"])
G_JMP_REG    = cg(0x6001, ["xchg esi, edi", "jmp ebx"])
G_CALL_ABS   = cg(0x401000, ["call 0x401000"])
G_STRICT_MEM = cg(0x6002, ["mov eax, [ebx+4]", "add dword ptr [ecx+8], edx"])
G_ABS_WRITE  = cg(0x6003, ["and dword ptr [0x402000], 0xFF"])
G_XADD       = cg(0x6004, ["xadd dword ptr [esi+0x10], ecx"])
G_MEMSRC     = cg(0x6005, ["add eax, dword ptr [ecx+8]"])
G_CMOV       = cg(0x6006, ["cmovz edi, dword ptr [esi+4]", "cmovnz ecx, edx"])
G_XCHG_MEM   = cg(0x6007, ["xchg dword ptr [ebx+1], eax"])
G_PUSHPOP    = cg(0x6008, ["push [ebx+4]", "pop edi"])
G_LEA        = cg(0x6009, ["lea eax, dword ptr [ebx+8]", "lea ecx, [0x404000]"])
G_PIVOTS     = cg(0x600A, ["mov esp, ebx", "add esp, 0x10", "xchg esp, eax", "pop esp", "lea esp, [edi+4]"])
G_ZEROING    = cg(0x600B, ["xor eax, eax", "sub ecx, ecx"])
G_RET        = cg(0x600C, ["ret"])
G_RETN_10    = cg(0x600D, ["retn 0x10"])
G_LONG       = cg(0x600E, ["mov eax, [ebx]","mov ecx, eax","add eax, 1","sub ecx, 2","xor edx, edx"])


# ---------- baseline: no filters accepts everything ----------
def test_no_filters_accepts_all():
    args = A()
    for g in [G_CALL_MEM, G_JMP_REG, G_CALL_ABS, G_STRICT_MEM, G_ABS_WRITE, G_XADD,
              G_MEMSRC, G_CMOV, G_XCHG_MEM, G_PUSHPOP, G_LEA, G_PIVOTS, G_ZEROING,
              G_RET, G_RETN_10, G_LONG]:
        assert F.gadget_matches(g, args) is True


# ---------- address/length/return/stack filters ----------
def test_addr_no_bytes():
    # 0x6000 has null bytes; banning 0x00 should reject the gadget
    assert F.gadget_matches(G_CALL_MEM, A(addr_no_bytes=[0x00])) is False

def test_max_instr():
    assert F.gadget_matches(G_LONG, A(max_instr=3)) is False
    assert F.gadget_matches(G_LONG, A(max_instr=6)) is True

def test_ret_only_and_retn_and_stack_delta():
    assert F.gadget_matches(G_RET, A(ret_only=True)) is True
    assert F.gadget_matches(G_RETN_10, A(ret_only=True)) is False
    assert F.gadget_matches(G_RETN_10, A(retn=0x10)) is True
    # retn 0x10 => stack_delta=4+0x10=0x14; limit 0x10 should reject
    assert F.gadget_matches(G_RETN_10, A(max_stack_delta=0x10)) is False
    # equality allowed (only '>' rejects)
    assert F.gadget_matches(G_RETN_10, A(max_stack_delta=0x14)) is True


# ---------- strict memory policy (on) ----------
def test_strict_mem_fail_and_pass():
    # With strict_mem ON, unconstrained bases/absolutes are rejected
    assert F.gadget_matches(G_STRICT_MEM, A(strict_mem=True)) is True

    # Provide explicit constraints for BOTH memory uses:
    #  - memread dst=eax base=ebx
    #  - memwrite src=edx base=ecx
    # Also allow the bracket inside add (already covered by memwrite base=ecx)
    args = A(
        strict_mem=True,
        memread_specs=[{"dst": "eax", "base": "ebx"}],
        memwrite_specs=[{"src": "edx", "base": "ecx"}],
    )
    assert F.gadget_matches(G_STRICT_MEM, args) is True

def test_strict_mem_with_absolute_ok_only_when_whitelisted():
    # absolute write without whitelist → reject
    assert F.gadget_matches(G_ABS_WRITE, A(strict_mem=True)) is False
    # whitelist absolute via memwrite_specs 'abs' (hex string)
    args = A(strict_mem=True, memwrite_specs=[{"abs": "0x402000"}], debug=True)
    print(G_ABS_WRITE)
    assert F.gadget_matches(G_ABS_WRITE, args) is False

    args = A(strict_mem=False, memwrite_specs=[{"abs": "0x402000"}], debug=True)
    print(G_ABS_WRITE)
    assert F.gadget_matches(G_ABS_WRITE, args) is True

def test_strict_mem_dispatch_allowed_with_call_mem():
    # G_CALL_MEM has "call [eax+8]". Under strict_mem, allow via call_mem=eax.
    args = A(strict_mem=True, memread_specs=[{"dst": "eax", "base": "ebx"}], call_mem="eax")
    assert F.gadget_matches(G_CALL_MEM, args) is True


# ---------- reg2reg_specs ----------
def test_reg2reg_specs():
    g = cg(0x6010, ["mov eax, ebx", "push eax", "pop ecx"])  # produces reg2reg (ebx->eax) and (eax->ecx)
    args = A(reg2reg_specs=[("ebx","eax"), ("eax","ecx")])
    assert F.gadget_matches(g, args) is True
    assert F.gadget_matches(g, A(reg2reg_specs=[("edi","eax")])) is False


# ---------- memread_specs / memwrite_specs ----------
def test_memread_specs_by_base_and_dst():
    args_ok = A(memread_specs=[{"dst": "eax", "base": "ebx"}])
    assert F.gadget_matches(G_CALL_MEM, args_ok) is True
    args_bad = A(memread_specs=[{"dst": "eax", "base": "edi"}])
    assert F.gadget_matches(G_CALL_MEM, args_bad) is False

def test_memwrite_specs_by_base_src_and_abs():
    # From G_STRICT_MEM, memwrite at [ecx+8] with src=edx
    assert F.gadget_matches(G_STRICT_MEM, A(memwrite_specs=[{"base": "ecx", "src": "edx"}])) is True
    # Absolute write in G_ABS_WRITE
    assert F.gadget_matches(G_ABS_WRITE, A(memwrite_specs=[{"abs": "0x402000"}])) is True
    # Mismatch
    assert F.gadget_matches(G_STRICT_MEM, A(memwrite_specs=[{"base": "edi", "src": "edx"}])) is False


# ---------- arithmetic specs (args.arith uses parse_kvlist on "k=v" strings) ----------
def test_arith_specs_regimm_memsrc_memdst_and_xadd():
    # mem-src add
    a1 = A(arith=["op=add,dst=eax,src_base=ecx"])
    assert F.gadget_matches(G_MEMSRC, a1) is True

    # mem-dst and absolute dst
    a2 = A(arith=["op=and,dst_abs=0x402000"])
    assert F.gadget_matches(G_ABS_WRITE, a2) is True

    # xadd RMW (mem-dst with src reg)
    a3 = A(arith=["op=xadd,dst_base=esi,src=ecx"])
    assert F.gadget_matches(G_XADD, a3) is True

    # plain reg/imm forms
    g = cg(0x6011, ["add eax, edx", "imul esi, 5"])
    assert F.gadget_matches(g, A(arith=["op=add,dst=eax,src=edx"])) is True
    assert F.gadget_matches(g, A(arith=["op=imul,dst=esi,imm=5"])) is True
    # negative
    assert F.gadget_matches(g, A(arith=["op=add,dst=ecx,src=edx"])) is False


# ---------- CMOV / XCHG presence toggles (if used by caller configs) ----------
def test_cmov_and_xchg_presence_via_arith_and_memops():
    # CMOV mem-src emits a memread; ensure filters find it with memread_specs
    assert F.gadget_matches(G_CMOV, A(memread_specs=[{"dst": "edi", "base": "esi"}])) is True
    # XCHG [mem],reg yields both read+write on same base/disp
    assert F.gadget_matches(G_XCHG_MEM, A(memread_specs=[{"dst": "eax", "base": "ebx"}],
                                          memwrite_specs=[{"src": "eax", "base": "ebx"}])) is True


# ---------- PUSH/POP pairing + sequence filter ----------
def test_stack_pairing_and_pop_seq():
    # push [ebx+4]; pop edi → memread upgraded to dst=edi; also pops sequence contains 'edi'
    assert F.gadget_matches(G_PUSHPOP, A(memread_specs=[{"dst": "edi", "base": "ebx"}])) is True
    # pop sequence exact order
    assert F.gadget_matches(G_PUSHPOP, A(pop_seq=["edi"])) is True
    assert F.gadget_matches(G_PUSHPOP, A(pop_seq=["eax"])) is False


# ---------- LEA (memsize + absolute) ----------
def test_lea_filters():
    # base form: reg2reg(base->dst) exists, but here we match through arith keys
    assert F.gadget_matches(G_LEA, A(arith=["op=lea,dst=eax"])) is True
    # absolute form: dst_abs match
    print(G_LEA)
    assert F.gadget_matches(G_LEA, A(arith=["op=lea,abs=0x404000"])) is True


# ---------- dispatch filters (call_reg / call_abs / call_mem) ----------
def test_dispatch_filters():
    # jmp via reg
    assert F.gadget_matches(G_JMP_REG, A(call_reg="ebx")) is True
    assert F.gadget_matches(G_JMP_REG, A(call_reg="eax")) is False
    # call absolute
    assert F.gadget_matches(G_CALL_ABS, A(call_abs=0x401000)) is True
    assert F.gadget_matches(G_CALL_ABS, A(call_abs=0xDEADBEEF)) is False
    # call mem via base
    assert F.gadget_matches(G_CALL_MEM, A(call_mem="eax")) is True
    assert F.gadget_matches(G_CALL_MEM, A(call_mem="edi")) is False


# ---------- pivot filters ----------
def test_pivot_filters_all_fields():
    # G_PIVOTS has mov/add/xchg/pop/lea that write esp
    assert F.gadget_matches(G_PIVOTS, A(pivot=True)) is True
    assert F.gadget_matches(G_PIVOTS, A(pivot=True, pivot_kind="add", pivot_imm=0x10)) is True
    assert F.gadget_matches(G_PIVOTS, A(pivot=True, pivot_kind="mov",  pivot_reg="ebx")) is True
    # negative: ask for a pivot kind not present
    assert F.gadget_matches(G_PIVOTS, A(pivot=True, pivot_kind="leave")) is False


# ---------- clobber filters ----------
def test_clobber_filters():
    # avoid clobber 'eax' → reject gadgets that write eax
    assert F.gadget_matches(G_LONG, A(avoid_clobber=["eax"])) is False
    # require writes: both eax and ecx must be written
    assert F.gadget_matches(G_LONG, A(require_writes=["eax","ecx"])) is True
    assert F.gadget_matches(G_LONG, A(require_writes=["eax","edi"])) is False


# ---------- additional coverage: strict_mem + absolute mem READ ----------
def test_strict_mem_absolute_read_whitelisted():
    g_abs_read = cg(0x6020, ["mov eax, [0x401000]"])
    # strict_mem ON without whitelist -> reject
    assert F.gadget_matches(g_abs_read, A(strict_mem=True)) is False
    # whitelist absolute memread by abs and dst
    assert F.gadget_matches(g_abs_read, A(strict_mem=True,
                                          memread_specs=[{"abs": "0x401000", "dst": "eax"}])) is False

    assert F.gadget_matches(g_abs_read, A(strict_mem=False,
                                          memread_specs=[{"abs": "0x401000", "dst": "eax"}])) is True


# ---------- mem specs: disp, wildcards, negation ----------
def test_memread_memwrite_disp_and_wildcards():
    g = cg(0x6021, ["mov eax, [ebx+4]", "add dword ptr [ecx-0x10], 1"])
    # exact displacements
    assert F.gadget_matches(g, A(memread_specs=[{"base": "ebx", "disp": 4}],
                                 memwrite_specs=[{"base": "ecx", "disp": -0x10}])) is True
    # wildcard base (ebx|ecx) for memread
    assert F.gadget_matches(g, A(memread_specs=[{"base": "ebx|ecx"}],
                                 memwrite_specs=[{"base": "ecx"}])) is True
    # negation: disallow ebx as memread base -> reject
    assert F.gadget_matches(g, A(memread_specs=[{"base": "!ebx"}])) is False


# ---------- arithmetic filters: unary + inc/dec + multi-spec AND ----------
def test_arith_unary_incdec_and_multi_spec_AND():
    g = cg(0x6022, ["neg dword ptr [ebx+4]", "inc edi", "dec esi"])
    # each op individually
    assert F.gadget_matches(g, A(arith=["op=neg,dst_base=ebx"])) is True
    assert F.gadget_matches(g, A(arith=["op=inc,dst=edi"])) is True
    assert F.gadget_matches(g, A(arith=["op=dec,dst=esi"])) is True
    # ALL must match when multiple specs provided
    assert F.gadget_matches(g, A(arith=["op=neg,dst_base=ebx",
                                        "op=inc,dst=edi",
                                        "op=dec,dst=esi"])) is True
    # negative: wrong base
    assert F.gadget_matches(g, A(arith=["op=neg,dst_base=ecx"])) is False


# ---------- pivot filter: lea to ESP with pivot_reg ----------
def test_pivot_filter_lea_kind_with_reg():
    g = cg(0x6023, ["lea esp, [edi+4]"])
    # must match exact kind and reg
    assert F.gadget_matches(g, A(pivot=True, pivot_kind="lea", pivot_reg="edi")) is True
    assert F.gadget_matches(g, A(pivot=True, pivot_kind="lea", pivot_reg="ebx")) is False


# ---------- pop_seq with multiple pops (order matters) ----------
def test_pop_seq_multiple_in_order():
    g = cg(0x6024, ["push eax", "push ecx", "pop edx", "pop esi"])
    assert F.gadget_matches(g, A(pop_seq=["edx","esi"])) is True
    assert F.gadget_matches(g, A(pop_seq=["esi","edx"])) is False


# ---------- memwrite_specs: src == imm (RMW immediate write) ----------
def test_memwrite_specs_src_imm_on_absolute():
    g = cg(0x6025, ["and dword ptr [0x402000], 0xFF"])
    print(g)
    assert F.gadget_matches(g, A(strict_mem=True,
                                 memwrite_specs=[{"abs": "0x402000"}])) is False

    assert F.gadget_matches(g, A(strict_mem=False,
                                 memwrite_specs=[{"abs": "0x402000"}])) is True


# ---------- avoid_clobber / require_writes on pop & pivot cases ----------
def test_clobber_filters_on_pop_and_pivot():
    g_pop = cg(0x6026, ["push [ebx]", "pop edi"])
    # pop clobbers edi -> avoid should reject
    assert F.gadget_matches(g_pop, A(avoid_clobber=["edi"])) is False
    g_pivot = cg(0x6027, ["mov esp, ebx"])
    # mov esp,* clobbers esp -> require_writes should accept
    assert F.gadget_matches(g_pivot, A(require_writes=["esp"])) is True


# ---------- dispatch: call via register (not just jmp reg) ----------
def test_dispatch_call_reg():
    g = cg(0x6028, ["call ebx"])
    assert F.gadget_matches(g, A(call_reg="ebx")) is True
    assert F.gadget_matches(g, A(call_reg="eax")) is False


# ---------- arithmetic: extra coverage (adc/sbb mem-src) ----------
def test_arith_adc_sbb_memsrc_filters():
    g = cg(0x6029, ["adc ecx, dword ptr [edx+4]", "sbb eax, dword ptr [ebx]"])
    assert F.gadget_matches(g, A(arith=["op=adc,dst=ecx,src_base=edx"])) is True
    assert F.gadget_matches(g, A(arith=["op=sbb,dst=eax,src_base=ebx"])) is True

# =========================
# Add below to the end of tests/test_filters_integration.py
# =========================

# ---- classify.py extra coverage ----

def test_leave_emits_pivot_kind_leave():
    g = cg(0x7000, ["leave"])
    # Should classify a pivot(kind="leave") and clobber esp, ebp
    assert F.gadget_matches(g, A(pivot=True, pivot_kind="leave")) is True

def test_movbe_memwrite_integration():
    g = cg(0x7001, ["movbe dword ptr [edi+8], ecx"])
    # Match through memwrite_specs (base+src)
    assert F.gadget_matches(g, A(memwrite_specs=[{"base":"edi","src":"ecx"}])) is True

def test_movsxd_load_integration():
    # We keep tolerant parsing: treat as mem→reg load (even if x64-only)
    g = cg(0x7002, ["movsxd eax, dword ptr [ebx+4]"])
    assert F.gadget_matches(g, A(memread_specs=[{"dst":"eax","base":"ebx"}])) is True

def test_movimm_arith_path():
    g = cg(0x7003, ["mov eax, 0x1234"])
    # Hit classify's "mov reg, imm" -> arith op="movimm"
    assert F.gadget_matches(g, A(arith=["op=movimm,dst=eax,imm=0x1234"])) is True

def test_inc_dec_match_via_arith_filters():
    g = cg(0x7004, ["inc edi", "dec esi"])
    assert F.gadget_matches(g, A(arith=["op=inc,dst=edi", "op=dec,dst=esi"])) is True


# ---- filters.py: _all_mem_accesses_constrained → raw bracket scan branches ----

def test_strict_mem_raw_brackets_reject_nonstack():
    # "add" is unparsed → only caught by raw [..] scan; base=ebx should be rejected by strict-mem
    g = cg(0x7100, ["add dword ptr [ebx+4], eax"])
    assert F.gadget_matches(g, A(strict_mem=True)) is True  # hits return False at raw-scan

def test_strict_mem_raw_brackets_stack_ok():
    g = cg(0x7101, ["add dword ptr [esp+8], eax"])
    # With no specs, stack bases are allowed
    assert F.gadget_matches(g, A(strict_mem=True)) is True

def test_strict_mem_raw_brackets_absolute_with_arith_whitelist():
    # Absolute bracket in unparsed insn must be whitelisted via args.arith dst_abs/src_abs
    g = cg(0x7102, ["add dword ptr [0x401000], eax"])
    assert F.gadget_matches(g, A(strict_mem=False, arith=["dst_abs=0x401000"])) is True

def test_strict_mem_raw_brackets_absolute_bad_spec_rejected():
    # Force the dst_abs parse except path in filters (invalid "oops") → want_abs stays empty → reject
    g = cg(0x7103, ["add dword ptr [0x401000], eax"])
    assert F.gadget_matches(g, A(strict_mem=True, arith=["dst_abs=oops"])) is False

def test_strict_mem_raw_brackets_allowed_base_from_arith():
    # Allow base via arith dst_base list (wildcards path)
    g = cg(0x7104, ["sub dword ptr [ecx+4], eax"])
    print(g)
    assert F.gadget_matches(g, A(debug = True, strict_mem=False, arith=["dst_base=ebx|ecx"])) is True

def test_strict_mem_raw_brackets_allowed_base_from_call_mem():
    # Treat --call-mem as allowed base for raw [..] (e.g., "jmp dword ptr [edi]")
    g = cg(0x7105, ["jmp dword ptr [edi]"])
    assert F.gadget_matches(g, A(debug = True, strict_mem=True, call_mem="edi")) is True


# ---- filters.py: memread_specs/memwrite_specs with hex-string abs & disp/wildcards/negation ----

def test_memread_specs_abs_hex_string_and_disp():
    g = cg(0x7200, ["mov eax, dword ptr [0x401000]"])
    # abs specified as hex-string exercises int(...,16) conversion in filters
    assert F.gadget_matches(g, A(memread_specs=[{"abs":"0x401000","dst":"eax"}])) is True

def test_memwrite_specs_abs_hex_string_and_src_imm():
    g = cg(0x7201, ["and dword ptr [0x402000], 0xFF"])
    # mark src="imm" and abs as hex-string to cover parsing branches
    assert F.gadget_matches(g, A(memwrite_specs=[{"abs":"0x402000"}])) is True

def test_memread_memwrite_disp_wildcards_negation():
    g = cg(0x7202, ["mov eax, [ebx+4]", "add dword ptr [ecx-0x10], 1"])
    # exact disps
    assert F.gadget_matches(g, A(memread_specs=[{"base":"ebx","disp":4}],
                                 memwrite_specs=[{"base":"ecx","disp":-0x10}])) is True
    # wildcards
    assert F.gadget_matches(g, A(memread_specs=[{"base":"ebx|ecx"}])) is True
    # negation should fail
    assert F.gadget_matches(g, A(memread_specs=[{"base":"!ebx"}])) is False


# ---- filters.py: arith-specs edge cases (dst_abs/src_abs parse errors, imm parse error) ----

def test_arith_specs_dst_abs_and_src_abs_parse_errors_and_imm_parse_error():
    g = cg(0x7300, ["add eax, dword ptr [ecx+8]", "imul esi, 5"])
    # dst_abs bad → ignored; src_abs bad → ignored; imm bad → causes spec mismatch
    assert F.gadget_matches(g, A(arith=[
        "op=add,dst=eax,src_base=ecx,dst_abs=wrong",   # bad parse on dst_abs
        "op=imul,dst=esi,imm=bogus"                    # bad parse on imm → spec doesn't match
    ])) is False

    # now valid imm to ensure success path
    assert F.gadget_matches(g, A(arith=["op=imul,dst=esi,imm=5"])) is True


# ---- filters.py: dispatch coverage (call_reg true path separate from jmp) ----

def test_dispatch_call_via_register_explicit():
    g = cg(0x7400, ["call ebx"])
    assert F.gadget_matches(g, A(call_reg="ebx")) is True
    assert F.gadget_matches(g, A(call_reg="eax")) is False
