# ropfilter/classify.py  (v0.2.17 + unified pivot synthesis)
from __future__ import annotations
import re
from typing import List
from .models import Gadget, MemOp, Pivot, Dispatch
from .utils import clean, is_reg, parse_imm, parse_mem_operand, canon_reg, norm_reg, get_exact_reg_mode


# === DEBUG TRACE HOOKS (auto-inserted) ===
# Uses ropfilter.debuglog.DebugLog if available, else falls back to a no-op.
try:
    from .debuglog import DebugLog, _NullLogger
except Exception:
    try:
        from debuglog import DebugLog, _NullLogger  # type: ignore
    except Exception:  # extremely defensive
        class _NullLogger:
            def emit(self, *_a, **_kw): pass
            def close(self): pass
        class DebugLog:  # shim
            def __init__(self, path: str): pass
            def emit(self, event: str, **fields): pass
            def close(self): pass

import os
import threading

def _get_logger():
    # Prefer the shared logger initialized by solver (if present)
    try:
        from . import solver as _solver_mod  # type: ignore
        lg = getattr(_solver_mod, "_DBG", None)
        if lg is not None:
            return lg
    except Exception:
        pass
    # env var fallback (lets you trace parsing/classify before solver starts)
    path = os.environ.get("ROPFILTER_DEBUG_FILE") or os.environ.get("ROP_DEBUG_FILE")
    if path:
        try:
            # Cache one instance per-thread via attribute on function (cheap)
            if not hasattr(_get_logger, "_cached"):
                _get_logger._cached = DebugLog(path)  # type: ignore[attr-defined]
            return _get_logger._cached  # type: ignore[attr-defined]
        except Exception:
            pass
    return _NullLogger()

def _safe(val, maxlen: int = 12000):
    try:
        if isinstance(val, (int, float, str, bool)) or val is None:
            return val
        if isinstance(val, (list, tuple)):
            if len(val) > 8:
                return {"type": type(val).__name__, "len": len(val), "head": [_safe(x) for x in val[:8]]}
            return [_safe(x) for x in val]
        if isinstance(val, dict):
            out = {}
            for k, v in list(val.items())[:16]:
                out[str(k)] = _safe(v)
            if len(val) > 16:
                out["..."] = f"+{len(val)-16} more"
            return out
        # Special-case Gadget-like objects
        addr = getattr(val, "address", None)
        text = getattr(val, "text", None)
        if addr is not None and text is not None:
            return {"Gadget": hex(addr), "text": text[:maxlen] + ("…" if len(text) > maxlen else "")}
        return repr(val)[:maxlen] + ("…" if len(repr(val)) > maxlen else "")
    except Exception as e:
        return f"<unserializable: {e}>"

def _trace(func):
    name = f"{__name__}.{func.__name__}"
    def wrapper(*args, **kwargs):
        lg = _get_logger()
        try:
            lg.emit("enter", func=name, args=[_safe(a) for a in args], kwargs={k:_safe(v) for k,v in kwargs.items()})
        except Exception:
            pass
        try:
            result = func(*args, **kwargs)
            try:
                lg.emit("return", func=name, result=_safe(result))
            except Exception:
                pass
            return result
        except Exception as e:
            try:
                lg.emit("error", func=name, etype=type(e).__name__, error=str(e))
            except Exception:
                pass
            raise
    wrapper.__name__ = func.__name__
    wrapper.__doc__ = func.__doc__
    wrapper.__qualname__ = func.__qualname__
    return wrapper
# === END DEBUG TRACE HOOKS ===



# -------------------------
# Core regex atoms / pieces
# -------------------------
REG      = r"[a-z][a-z0-9]*"
MEMSIZE  = r"(?:byte|word|dword|qword)\s+(?:ptr\s+)?"

# Accept optional size/ptr before bracketed operands, e.g. "dword [eax]"
SIZEPTR_BRACKET_RE = re.compile(rf"^(?:{MEMSIZE})?\[(.+?)\]$", re.I)

# ----------------
# Frame & control
# ----------------
RET_RE    = re.compile(r"^\s*ret[n]?\s*(0x[0-9a-fA-F]+|\d+)?\s*$", re.I)
LEAVE_RE  = re.compile(r"^\s*leave\s*$", re.I)
CALL_RE   = re.compile(r"^\s*call\s+(.+?)\s*$", re.I)
JMP_RE    = re.compile(r"^\s*jmp\s+(.+?)\s*$", re.I)

# -------------
# PUSH / POP
# -------------
# Robust (whitespace tolerant) forms
PUSH_RE       = re.compile(r"^\s*push\s+(.+?)\s*$", re.I)
POP_RE        = re.compile(r"^\s*pop\s+([a-z0-9]+)\s*$", re.I)  # pop reg
PUSH_MEM_RE   = re.compile(rf"^\s*push\s+(?:{MEMSIZE})?\[(.+?)\]\s*$", re.I)
POP_MEM_RE    = re.compile(rf"^\s*pop\s+(?:{MEMSIZE})?\[(.+?)\]\s*$", re.I)
PUSH_REG_RE   = re.compile(r"^\s*push\s+([a-z0-9]+)\s*$", re.I)
POP_REG_RE    = re.compile(r"^\s*pop\s+([a-z0-9]+)\s*$", re.I)

# -----------
# MOV family
# -----------
# Keep legacy regexes; extend coverage below.
MOV_RE        = re.compile(r"^\s*mov\s+([^,]+)\s*,\s*(.+?)\s*$", re.I)
MEMREAD_RE    = re.compile(rf"^\s*mov\s+([a-z0-9]+)\s*,\s*(?:{MEMSIZE})?\[(.+?)\]\s*$", re.I)
MEMWRITE_RE   = re.compile(rf"^\s*mov\s*(?:{MEMSIZE})?\[(.+?)\]\s*,\s*([a-z0-9]+)\s*$", re.I)
MOVZX_RE      = re.compile(rf"^\s*movz[xq]?\s+([a-z0-9]+)\s*,\s*(?:{MEMSIZE})?\[(.+?)\]\s*$", re.I)
MOVSX_RE      = re.compile(rf"^\s*movs[xq]?\s+([a-z0-9]+)\s*,\s*(?:{MEMSIZE})?\[(.+?)\]\s*$", re.I)

# movbe (load/store) and movsxd (present in file; harmless in x86-only inputs)
MOVBE_MEMREAD_RE  = re.compile(rf"^\s*movbe\s+([a-z0-9]+)\s*,\s*(?:{MEMSIZE})?\[(.+?)\]\s*$", re.I)
MOVBE_MEMWRITE_RE = re.compile(rf"^\s*movbe\s*(?:{MEMSIZE})?\[(.+?)\]\s*,\s*([a-z0-9]+)\s*$", re.I)
MOVSXD_RE         = re.compile(rf"^\s*movsxd\s+([a-z0-9]+)\s*,\s*(?:{MEMSIZE})?\[(.+?)\]\s*$", re.I)

# CMOVcc with optional memsize and either mem or reg source
CMOV_MEMSRC_RE = re.compile(
    r"^\s*cmov[a-z]{1,3}\s+([a-z0-9]+)\s*,\s*(?:" + MEMSIZE + r")?\[(.+?)\]\s*$",
    re.I,
)
CMOV_REGSRC_RE = re.compile(
    r"^\s*cmov[a-z]{1,3}\s+([a-z0-9]+)\s*,\s*([a-z0-9]+)\s*$",
    re.I,
)

# ---------------
# XCHG (extended)
# ---------------
XCHG_RE           = re.compile(r"^\s*xchg\s+([a-z0-9]+)\s*,\s*([a-z0-9]+)\s*$", re.I)
XCHG_MEM_REG_RE   = re.compile(rf"^\s*xchg\s+(?:{MEMSIZE})?\[(.+?)\]\s*,\s*([a-z0-9]+)\s*$", re.I)
XCHG_REG_MEM_RE   = re.compile(rf"^\s*xchg\s+([a-z0-9]+)\s*,\s*(?:{MEMSIZE})?\[(.+?)\]\s*$", re.I)

# ---------------
# LEA & ARITH/LOG
# ---------------
LEA_RE = re.compile(rf"^\s*lea\s+([^,]+)\s*,\s*(?:{MEMSIZE})?(\[[^\]]+\])\s*$", re.I)


# Unified ARITH (incl. XADD). Unary handled separately.
ARITH_RE          =  re.compile(r"^\s*(add|sub|xor|or|and|adc|sbb|imul|xadd|ror|rcr)\s+([a-z0-9]+)\s*,\s*(.+?)\s*$", re.I)
ARITH_MEMDST_RE   = re.compile(rf"^\s*(add|sub|xor|or|and|adc|sbb|imul|xadd|ror|rcr)\s+(?:{MEMSIZE})?\[(.+?)\]\s*,\s*(.+?)\s*$", re.I)
ARITH_MEMSRC_RE   = re.compile(rf"^\s*(add|sub|xor|or|and|adc|sbb|imul|ror|rcr)\s+([a-z0-9]+)\s*,\s*(?:{MEMSIZE})?\[(.+?)\]\s*$", re.I)

NEG_RE            = re.compile(r"^\s*neg\s+(.+?)\s*$", re.I)
INCDEC_RE         = re.compile(r"^\s*(inc|dec)\s+([a-z0-9]+)\s*$", re.I)



def classify_gadget(address: int, instrs: List[str]) -> Gadget:
    g = Gadget(address, " ; ".join(instrs), instrs, len(instrs), None, None)

    # Ensure expected attributes exist (back-compat friendly)
    if not hasattr(g, "reg2reg_pos"): g.reg2reg_pos = []
    if not hasattr(g, "pop_pos"):     g.pop_pos = []

    lifo: List[str] = []              # for inline reg2reg push;pop synthesis
    _pending_pushes: List[dict] = []  # to pair push...pop[mem]
    saw_leave = False                 # to synthesize 'leave' pivot later

    # push/pop counters for net-balance check (only expose g.excessive_pushes)
    push_ct = 0
    pop_ct  = 0

    for i, raw in enumerate(instrs):
        handled = False

        ins = clean(raw)
        if not ins:
            continue

        # -------- RET / RETN imm --------
        m = RET_RE.match(ins)
        if m:
            if m.group(1):
                handled = True
                g.ret_imm = parse_imm(m.group(1))
                g.stack_delta = 4 + (g.ret_imm or 0)
            else:
                g.ret_imm = 0
                g.stack_delta = 4
            continue

        # -------- LEAVE --------
        if LEAVE_RE.match(ins):
            # leave = mov esp, ebp ; pop ebp
            for r in ("esp", "ebp"):
                if r not in g.clobbers: g.clobbers.append(r)
            handled = True
            saw_leave = True
            continue

        # -----------------------------------
        # PUSH/POP with memory (pair-aware) + inline push;pop reg2reg synthesis
        # -----------------------------------
        m = PUSH_MEM_RE.match(ins)
        if m:
            mem_inner = "[" + m.group(1) + "]"
            base, disp, absaddr = parse_mem_operand(mem_inner)
            _pending_pushes.append({"kind": "mem", "base": base, "disp": disp, "abs": absaddr})
            # record read from memory into stack (upgraded to reg if immediately popped)
            g.memreads.append(MemOp(dst="stack", base=base, disp=disp, absolute=absaddr, op='push', idx=i))
            handled = True
            push_ct += 1
            continue

        m = POP_MEM_RE.match(ins)
        if m:
            mem_inner = "[" + m.group(1) + "]"
            base, disp, absaddr = parse_mem_operand(mem_inner)

            # Pair against prior push where possible
            if _pending_pushes:
                top = _pending_pushes.pop()
                if top["kind"] == "reg":
                    # push <reg> ; pop [mem]  => write that reg to memory
                    src_reg = top["reg"]
                    g.memwrites.append(MemOp(src=src_reg, base=base, disp=disp, absolute=absaddr, op='pop', idx=i))
                    handled = True
                elif top["kind"] == "mem":
                    # push [memA] ; pop [memB]  => data flowed via stack, still a write
                    g.memwrites.append(MemOp(src="stack", base=base, disp=disp, absolute=absaddr, op='pop', idx=i))
                    handled = True
            else:
                # Unpaired: stack -> mem write
                g.memwrites.append(MemOp(src="stack", base=base, disp=disp, absolute=absaddr, op='pop', idx=i))
                handled = True

            pop_ct += 1
            continue

        # Track push/pop reg for pairing & inline synthesis
        m = PUSH_REG_RE.match(ins)
        if m:
            tok = clean(m.group(1))
            if is_reg(tok):
                r = canon_reg(tok)
                lifo.append(r)                         # for reg2reg with a later POP_REG
                _pending_pushes.append({"kind": "reg", "reg": r})  # for POP_MEM pairing
                push_ct += 1
                handled = True
            continue

        # Attempt upgrade: push [mem] ... pop reg  ==> convert earlier memread dst="stack" → dst=<reg>
        m = POP_REG_RE.match(ins)
        if m:
            dreg = canon_reg(m.group(1))
            if dreg:
                # 1) If top pending push was a memory read, upgrade the latest matching MemOp
                if _pending_pushes and _pending_pushes[-1]["kind"] == "mem":
                    top = _pending_pushes.pop()
                    for op in reversed(g.memreads):
                        if op.dst == "stack" and op.base == top["base"] and op.disp == top["disp"] and op.absolute == top["abs"]:
                            op.dst = dreg
                            if dreg not in g.clobbers:
                                g.clobbers.append(dreg)
                            handled = True
                            break

                # 2) Inline synthesize push;pop reg2reg if last push was a reg
                if lifo:
                    src = lifo.pop()
                    g.reg2reg_pos.append(i)  # record POP index
                    g.reg2reg.append((src, dreg, "pushpop"))
                    if dreg not in g.clobbers:
                        g.clobbers.append(dreg)

                pop_ct += 1  # count the pop once
            # allow the POP_RE block to also add pops/clobbers bookkeeping

        # -------- POP reg (bookkeeping) --------
        mp = POP_RE.match(ins)
        if mp:
            d = canon_reg(mp.group(1))
            if d:
                handled = True
                g.pop_pos.append(i)
                g.pops.append(d)
                if d not in g.clobbers:
                    g.clobbers.append(d)
            continue

        # -----------------------------------
        # XCHG (mem & reg forms)
        # -----------------------------------
        mxm = XCHG_MEM_REG_RE.match(ins)
        if mxm:
            mem_inner, reg = "[" + mxm.group(1) + "]", canon_reg(mxm.group(2))
            if reg:
                base, disp, absaddr = parse_mem_operand(mem_inner)
                handled = True
                g.memreads.append(MemOp(dst=reg, base=base, disp=disp, absolute=absaddr, op='xchg', idx=i))
                g.memwrites.append(MemOp(src=reg, base=base, disp=disp, absolute=absaddr, op='xchg', idx=i))
                if reg not in g.clobbers: g.clobbers.append(reg)
            continue

        mxr = XCHG_REG_MEM_RE.match(ins)
        if mxr:
            reg, mem_inner = canon_reg(mxr.group(1)), "[" + mxr.group(2) + "]"
            if reg:
                handled = True
                base, disp, absaddr = parse_mem_operand(mem_inner)
                g.memreads.append(MemOp(dst=reg, base=base, disp=disp, absolute=absaddr, op='xchg', idx=i))
                g.memwrites.append(MemOp(src=reg, base=base, disp=disp, absolute=absaddr, op='xchg', idx=i))
                if reg not in g.clobbers: g.clobbers.append(reg)
            continue

        mx = XCHG_RE.match(ins)
        if mx:
            r1, r2 = canon_reg(mx.group(1)), canon_reg(mx.group(2))
            if r1 and r2:
                for r in (r1, r2):
                    if r not in g.clobbers: g.clobbers.append(r)
                g.reg2reg_pos.append(i)
                handled = True
                g.reg2reg += [(r1, r2, "xchg"), (r2, r1, "xchg")]
            continue

        # ---------------------
        # MOV / MOVZX / MOVSX
        # ---------------------

        # mov reg, [mem]
        mr = MEMREAD_RE.match(ins)
        if mr:
            d, inner = canon_reg(mr.group(1)), "[" + mr.group(2) + "]"
            if d:
                base, disp, absaddr = parse_mem_operand(inner)
                if d not in g.clobbers: g.clobbers.append(d)
                handled = True
                g.memreads.append(MemOp(dst=d, base=base, disp=disp, absolute=absaddr, op='mov', idx=i))
            continue

        # mov [mem], reg
        mw = MEMWRITE_RE.match(ins)
        if mw:
            inner, s = "[" + mw.group(1) + "]", canon_reg(mw.group(2))
            if s:
                base, disp, absaddr = parse_mem_operand(inner)
                handled = True
                g.memwrites.append(MemOp(src=s, base=base, disp=disp, absolute=absaddr, op='mov', idx=i))
            continue

        # movzx/movsx reg, [mem]
        mz = MOVZX_RE.match(ins)
        if mz:
            d, inner = canon_reg(mz.group(1)), "[" + mz.group(2) + "]"
            if d:
                base, disp, absaddr = parse_mem_operand(inner)
                if d not in g.clobbers: g.clobbers.append(d)
                handled = True
                g.memreads.append(MemOp(dst=d, base=base, disp=disp, absolute=absaddr, op='mov', idx=i))
            continue

        msx = MOVSX_RE.match(ins)
        if msx:
            d, inner = canon_reg(msx.group(1)), "[" + msx.group(2) + "]"
            if d:
                base, disp, absaddr = parse_mem_operand(inner)
                if d not in g.clobbers: g.clobbers.append(d)
                handled = True
                g.memreads.append(MemOp(dst=d, base=base, disp=disp, absolute=absaddr, op='mov', idx=i))
            continue

        # movbe reg, [mem]
        mbr = MOVBE_MEMREAD_RE.match(ins)
        if mbr:
            d, inner = canon_reg(mbr.group(1)), "[" + mbr.group(2) + "]"
            if d:
                base, disp, absaddr = parse_mem_operand(inner)
                if d not in g.clobbers: g.clobbers.append(d)
                handled = True
                g.memreads.append(MemOp(dst=d, base=base, disp=disp, absolute=absaddr, op='mov', idx=i))
            continue

        # movbe [mem], reg
        mbw = MOVBE_MEMWRITE_RE.match(ins)
        if mbw:
            inner, s = "[" + mbw.group(1) + "]", canon_reg(mbw.group(2))
            if s:
                base, disp, absaddr = parse_mem_operand(inner)
                handled = True
                g.memwrites.append(MemOp(src=s, base=base, disp=disp, absolute=absaddr, op='mov', idx=i))
            continue

        # movsxd reg, [mem]
        msxd = MOVSXD_RE.match(ins)
        if msxd:
            d, inner = canon_reg(msxd.group(1)), "[" + msxd.group(2) + "]"
            if d:
                base, disp, absaddr = parse_mem_operand(inner)
                if d not in g.clobbers: g.clobbers.append(d)
                handled = True
                g.memreads.append(MemOp(dst=d, base=base, disp=disp, absolute=absaddr, op='mov', idx=i))
            continue

        # mov reg, reg   |  mov reg, imm
        mm = MOV_RE.match(ins)
        if mm:
            dst, src = clean(mm.group(1)), clean(mm.group(2))

            # mov reg, reg
            if is_reg(dst) and is_reg(src):
                d, s = canon_reg(dst), canon_reg(src)
                if d and s:
                    if d not in g.clobbers: g.clobbers.append(d)
                    g.reg2reg_pos.append(i)
                    handled = True
                    g.reg2reg.append((s, d, "mov"))
                continue

            # mov reg, imm
            if is_reg(dst) and re.match(r"^(0x[0-9a-fA-F]+|\d+)$", src):
                d = canon_reg(dst)
                if d:
                    if d not in g.clobbers: g.clobbers.append(d)
                    handled = True
                    g.arith.append({"op": "movimm", "dst": d, "imm": parse_imm(src), "idx": i})
                continue

            continue  # fallthrough

        # ---- LEA ----
        ml = LEA_RE.match(ins)
        if ml:
            d = canon_reg(clean(ml.group(1)))
            mem = clean(ml.group(2))
            base, disp, absaddr = parse_mem_operand(mem)
            if d:
                if d not in g.clobbers: g.clobbers.append(d)
                if base and absaddr is None:
                    g.reg2reg_pos.append(i)
                    g.reg2reg.append((base, d, "lea"))
                handled = True
                g.arith.append({"op": "lea", "dst": d, "base": base, "disp": disp, "abs": absaddr, "idx": i})
            continue

        # -------------------------
        # CMOVcc (reg/mem source)
        # -------------------------
        m = CMOV_MEMSRC_RE.match(ins)
        if m:
            dst_reg = canon_reg(m.group(1))
            if dst_reg:
                base, disp, absaddr = parse_mem_operand("[" + m.group(2) + "]")
                handled = True
                g.memreads.append(MemOp(dst=dst_reg, base=base, disp=disp, absolute=absaddr, op='mov', idx=i))
                if dst_reg not in g.clobbers: g.clobbers.append(dst_reg)
            continue

        m = CMOV_REGSRC_RE.match(ins)
        if m:
            dst_reg, src_reg = canon_reg(m.group(1)), canon_reg(m.group(2))
            if dst_reg and src_reg:
                g.reg2reg_pos.append(i)
                handled = True
                g.reg2reg.append((src_reg, dst_reg, "mov"))
                if dst_reg not in g.clobbers: g.clobbers.append(dst_reg)
            continue

        # ------------------------------
        # ARITH / LOGIC (incl. XADD)
        # ------------------------------
        # [mem], reg|imm  (mem destination; xadd allowed only with reg)
        mm = ARITH_MEMDST_RE.match(ins)
        if mm:
            handled = True
            op, mem_inner, src_tok = mm.group(1).lower(), clean(mm.group(2)), clean(mm.group(3))
            base, disp, absaddr = parse_mem_operand("[" + mem_inner + "]")

            if op == "xadd":
                if is_reg(src_tok):
                    s = canon_reg(src_tok)
                    if s:
                        # semantic record
                        g.arith.append({"op": "xadd", "dst_mem": {"base": base, "disp": disp, "abs": absaddr}, "src": s, "idx": i})
                        # ALSO record a generic memwrite (RMW)
                        g.memwrites.append(MemOp(src="rmw", base=base, disp=disp, absolute=absaddr, op='add', idx=i))
                continue  # xadd [mem], imm is invalid; ignore

            # non-xadd RMW: add/sub/and/or/xor/adc/sbb/imul/...
            entry = {"op": op, "dst_mem": {"base": base, "disp": disp, "abs": absaddr}, "idx": i}

            if is_reg(src_tok):
                src_reg = canon_reg(src_tok)
                if src_reg:
                    entry["src"] = src_reg
                    g.memwrites.append(MemOp(src=src_reg, base=base, disp=disp, absolute=absaddr, op=op, idx=i))
            elif re.match(r"^(0x[0-9a-fA-F]+|\d+)$", src_tok):
                imm = parse_imm(src_tok)
                entry["imm"] = imm
                g.memwrites.append(MemOp(src="imm", base=base, disp=disp, absolute=absaddr, op=op, idx=i))
            else:
                g.memwrites.append(MemOp(src=None, base=base, disp=disp, absolute=absaddr, op=op, idx=i))

            g.arith.append(entry)
            continue

        # reg, [mem]  (read)
        ms = ARITH_MEMSRC_RE.match(ins)
        if ms:
            handled = True
            op, dst_tok, mem_inner = ms.group(1).lower(), canon_reg(ms.group(2)), clean(ms.group(3))
            if dst_tok:
                if dst_tok not in g.clobbers: g.clobbers.append(dst_tok)
                base, disp, absaddr = parse_mem_operand("[" + mem_inner + "]")
                entry = {"op": op, "dst": dst_tok, "src_mem": {"base": base, "disp": disp, "abs": absaddr}, "idx": i}
                g.arith.append(entry)
                # ALSO record a MemOp read for filters/tests
                g.memreads.append(MemOp(dst=dst_tok, base=base, disp=disp, absolute=absaddr, op=op, idx=i))
            continue

        # reg, reg|imm
        ma = ARITH_RE.match(ins)
        if ma:
            handled = True
            op, dst_tok, src_tok = ma.group(1).lower(), clean(ma.group(2)), clean(ma.group(3))
            if is_reg(dst_tok):
                d = canon_reg(dst_tok)
                if d:
                    if op == "xadd":
                        # xadd reg, reg   (xadd reg, imm invalid)
                        if is_reg(src_tok):
                            s = canon_reg(src_tok)
                            if s:
                                for r in (d, s):
                                    if r not in g.clobbers: g.clobbers.append(r)
                                g.arith.append({"op": "xadd", "dst": d, "src": s, "idx": i})
                        continue

                    entry = {"op": op, "dst": d, "idx": i}
                    if is_reg(src_tok):
                        s = canon_reg(src_tok)
                        if s:
                            entry["src"] = s
                    elif re.match(r"^(0x[0-9a-fA-F]+|\d+)$", src_tok):
                        entry["imm"] = parse_imm(src_tok)

                    # zeroing idioms
                    if op in ("xor", "sub"):
                        if (entry.get("src") == d) or (entry.get("imm") == 0):
                            if d not in g.zero: g.zero.append(d)

                    if d not in g.clobbers: g.clobbers.append(d)
                    g.arith.append(entry)
            continue

        # ---- unary ----
        mn = NEG_RE.match(ins)
        if mn:
            handled = True
            tok = clean(mn.group(1))
            msz = SIZEPTR_BRACKET_RE.match(tok)
            if msz:
                base, disp, absaddr = parse_mem_operand("[" + msz.group(1) + "]")
                g.arith.append({"op": "neg", "dst_mem": {"base": base, "disp": disp, "abs": absaddr}, "idx": i})
            else:
                d = canon_reg(tok)
                if d:
                    if d not in g.clobbers: g.clobbers.append(d)
                    g.arith.append({"op": "neg", "dst": d, "idx": i})
            continue

        mid = INCDEC_RE.match(ins)
        if mid:
            handled = True
            op, dst = mid.group(1).lower(), canon_reg(mid.group(2))
            if dst:
                if dst not in g.clobbers: g.clobbers.append(dst)
                g.arith.append({"op": op, "dst": dst, "imm": 1 if op == "inc" else -1, "idx": i})
            continue

        # -----------------------------
        # Indirect dispatch targets
        # -----------------------------
        for kind, RX in (("call", CALL_RE), ("jmp", JMP_RE)):
            mc = RX.match(ins)
            if mc:
                handled = True
                tgt = clean(mc.group(1))
                # reg target
                if is_reg(tgt):
                    g.dispatch.append(Dispatch(kind, "reg", reg=canon_reg(tgt)))
                    continue
                # memory target: support "[...]" and size/ptr prefixes
                msz = SIZEPTR_BRACKET_RE.match(tgt)
                if msz or tgt.startswith("["):
                    inner = "[" + (msz.group(1) if msz else tgt.strip("[]")) + "]"
                    base, disp, absaddr = parse_mem_operand(inner)
                    g.dispatch.append(Dispatch(kind, "mem", reg=base))
                    continue
                # absolute target
                if re.match(r"^0x[0-9a-fA-F]+$", tgt):
                    g.dispatch.append(Dispatch(kind, "abs", absolute=int(tgt, 16)))
                    continue

        # === Unified fallback for unmatched instructions (v0.2.26) ===
        if not handled:
            if not hasattr(g, "unclassified_reg_writes"):
                g.unclassified_reg_writes = []

            parts = ins.split(None, 1)
            if not parts:
                continue
            mnemonic = parts[0].lower()
            ops_txt = parts[1] if len(parts) > 1 else ""
            operands = [o.strip() for o in ops_txt.split(",")] if ops_txt else []

            def _parse_opnd(tok: str):
                t = tok.strip()
                msz = SIZEPTR_BRACKET_RE.match(t)
                if msz:
                    inner = "[" + msz.group(1) + "]"
                    base, disp, absaddr = parse_mem_operand(inner)
                    return {"kind": "mem", "mem": {"base": base, "disp": disp, "abs": absaddr}}
                if t.startswith("[") and t.endswith("]"):
                    base, disp, absaddr = parse_mem_operand(t)
                    return {"kind": "mem", "mem": {"base": base, "disp": disp, "abs": absaddr}}
                r = canon_reg(t)
                if r:
                    return {"kind": "reg", "reg": r}
                imm = parse_imm(t)
                if imm is not None:
                    return {"kind": "imm", "imm": imm}
                return {"kind": "raw", "raw": t}

            opnds = [_parse_opnd(o) for o in operands]

            entry = {"op": mnemonic, "idx": i}

            # implicit mem for string ops so --avoid-memref can act
            _str_ops_src_dst = {
                "movsb": ("esi", "edi"), "movsd": ("esi", "edi"),
                "cmpsb": ("esi", "edi"), "cmpsd": ("esi", "edi"),
                "lodsb": ("esi", None),  "lodsd": ("esi", None),
                "stosb": (None, "edi"),  "stosd": (None, "edi"),
                "scasb": (None, "edi"),  "scasd": (None, "edi"),
                "insb":  ("edi", None),  "insd":  ("edi", None),
            }
            if not operands and mnemonic in _str_ops_src_dst:
                sbase, dbase = _str_ops_src_dst[mnemonic]
                if sbase:
                    entry["src_mem"] = {"base": sbase, "disp": 0, "abs": None}
                if dbase:
                    entry["dst_mem"] = {"base": dbase, "disp": 0, "abs": None}

            SEG_LOADS = {"les", "lds", "lfs", "lgs", "lss"}

            dst_reg = None
            if opnds and opnds[0]["kind"] == "reg":
                dst_reg = opnds[0]["reg"]

            if len(opnds) == 0:
                pass
            elif len(opnds) == 1:
                k = opnds[0]["kind"]
                if k == "mem":
                    entry["src_mem"] = opnds[0]["mem"]
                elif k == "reg":
                    entry["dst"] = opnds[0]["reg"]
                elif k == "imm":
                    entry["imm"] = opnds[0]["imm"]
            else:
                dst_op, src_op = opnds[0], opnds[1]
                if dst_op["kind"] == "reg":
                    entry["dst"] = dst_op["reg"]
                elif dst_op["kind"] == "mem":
                    entry["dst_mem"] = dst_op["mem"]
                if src_op["kind"] == "reg":
                    entry["src"] = src_op["reg"]
                elif src_op["kind"] == "mem":
                    entry["src_mem"] = src_op["mem"]
                elif src_op["kind"] == "imm":
                    entry["imm"] = src_op["imm"]

            if mnemonic in SEG_LOADS:
                if not (len(opnds) >= 2 and opnds[1]["kind"] == "mem"):
                    entry["invalid"] = True

            g.unclassified_reg_writes.append(entry)

            # Also reflect a minimal "arith-like" event so stability checks can see clobbers
            if ("invalid" not in entry) and ("dst" in entry) and entry["dst"]:
                if entry["dst"] not in g.clobbers:
                    g.clobbers.append(entry["dst"])
                a = {"op": mnemonic, "dst": entry["dst"], "idx": i}
                if "src" in entry:
                    a["src"] = entry["src"]
                if "imm" in entry:
                    a["imm"] = entry["imm"]
                g.arith.append(a)
            continue

    # net-push check requested: True if total pushes > total pops
    g.excessive_pushes = (push_ct > pop_ct)

    # -------------------------------
    # unified pivot synthesis (x86)
    # -------------------------------
    seen = set()

    def _add_pivot(kind: str, reg: str | None = None, imm: int | None = None):
        key = (kind, reg, imm)
        if key in seen:
            return
        seen.add(key)
        g.pivot.append(Pivot(kind=kind, reg=reg, imm=imm))

    # a) pivots from reg2reg that write esp
    for src, dst, op in g.reg2reg:
        if dst == "esp":
            _add_pivot(op, reg=src)

    # b) pivots from arithmetic entries that write esp
    for e in g.arith:
        if e.get("dst") == "esp":
            kind = e.get("op")
            reg  = e.get("src")
            imm  = e.get("imm")
            if kind == "lea" and not reg:
                reg = e.get("base")
            _add_pivot(kind, reg=reg, imm=imm)

    # c) pivots from memory loads into esp
    for m in g.memreads:
        if m.dst == "esp":
            _add_pivot("mov")

    # d) pivot from 'pop esp'
    if any(r == "esp" for r in g.pops):
        _add_pivot("pop")

    # e) pivot from 'leave'
    if saw_leave:
        _add_pivot("leave")

    return g



# --- auto-wrap functions for debug trace ---

classify_gadget = _trace(classify_gadget)

# --- end auto-wrap ---
