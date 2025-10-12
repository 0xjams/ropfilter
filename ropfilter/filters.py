# ropfilter/filters.py
from __future__ import annotations


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


from typing import Any, Dict, List, Optional, Tuple

from .utils import (
    addr_has_bytes,
    parse_kvlist,
    reg_match,
    mem_spec_op_ok,
    norm_reg,  # <-- added
    set_exact_reg_mode,
    get_exact_reg_mode
)

def _same_phys_reg(a: Optional[str], b: Optional[str]) -> bool:
    """Treat split/partial regs as the same physical register family.
    Ignores --exact-reg on purpose so eax==ax==al==ah for stability checks.
    """
    if not a or not b:
        return False
    pa = norm_reg(a)
    pb = norm_reg(b)
    return (pa is not None) and (pb is not None) and (pa == pb)

# ------------------------------------------------------------
# Small helpers
# ------------------------------------------------------------
# v0.2.26 — normalize unclassified entries (dict or legacy tuple)
def _uncls_get(entry, key, default=None):
    if isinstance(entry, dict):
        return entry.get(key, default)
    # legacy tuple: (idx, mnemonic, dst, src)
    try:
        idx, mn, dst, src = entry
        mapping = {"idx": idx, "op": mn, "dst": dst, "src": src}
        return mapping.get(key, default)
    except Exception:
        return default


def _as_int_or_none(v):
    if v is None:
        return None
    if isinstance(v, int):
        return v
    try:
        return int(str(v).strip(), 0)
    except Exception:
        return None


# NEW: op-pattern matcher for --arith (supports *, a|b|c, and !a|b)
def _op_match(actual_op: Optional[str], pat: Optional[str]) -> bool:
    """
    Support *, alternation with '|', and negation with leading '!'.
      - pat None/""/"*"/"any" => wildcard (match any)
      - "add|sub|xor"         => actual_op must be one of these
      - "!add|sub"            => actual_op must be none of these
    """
    if pat is None:
        return True
    s = str(pat).strip().lower()
    if not s or s in ("*", "any"):
        return True
    op = (actual_op or "").strip().lower()

    neg = s.startswith("!")
    if neg:
        s = s[1:]
    opts = {t.strip() for t in s.split("|") if t.strip()}
    if not opts:
        # Empty list behaves like wildcard for negation; no-match otherwise
        return True if neg else False

    in_set = op in opts
    return (not in_set) if neg else in_set


# Indices helpers for smart --stable-dst
def _coerce_idx(v, default: int) -> int:
    if v is None:
        return default
    try:
        return int(v)
    except Exception:
        return default

def _get_idx(obj, default: int = -1) -> int:
    """
    Return an integer instruction index for an event-like object.
    Works for:
      - MemOp (attribute .idx which may be None),
      - arith dicts (key 'idx' which may be absent/None),
      - anything else → default.
    """
    if obj is None:
        return default
    if isinstance(obj, dict):
        return _coerce_idx(obj.get("idx", default), default)
    return _coerce_idx(getattr(obj, "idx", default), default)


def _later_overwrite_is_different(
    g,
    start_idx: int,
    dst: str,
    original_kind: str,
    meta: Dict[str, Any],
) -> bool:
    """
    Return True if there exists a *later* write to 'dst' (same physical register family)
    that is not equivalent to the original write described by (original_kind, meta).

    E.g., if dst is EAX, a later write to AL/AH/AX/EAX counts as an overwrite for stability checks,
    regardless of --exact-reg. Equivalence rules follow the original comments, but register
    comparisons use physical-family equality.
    """
    # Later MEMREAD writes into dst
    for mr in getattr(g, "memreads", []):
        if not _same_phys_reg(mr.dst, dst):
            continue
        j = _get_idx(mr, default=start_idx)  # If 'mr' lacks idx, treat as same (not later)
        if j <= start_idx:
            continue
        if original_kind == "memread":
            same_abs = (mr.absolute is not None and mr.absolute == meta.get("abs"))
            same_mem = (
                mr.absolute is None and meta.get("abs") is None
                and _same_phys_reg(mr.base, meta.get("base"))
                and mr.disp == meta.get("disp")
                and (mr.op or None) == (meta.get("op") or None)
            )
            if not (same_abs or same_mem):
                return True  # different memory later
        else:
            return True  # original was reg2reg or arith_reg: any later memread differs

    # Later REG2REG writes into dst
    reg2reg_pos = getattr(g, "reg2reg_pos", None)
    if reg2reg_pos is not None:
        for k, (s, d, _kind) in enumerate(getattr(g, "reg2reg", [])):
            if not _same_phys_reg(d, dst):
                continue
            j = _coerce_idx(reg2reg_pos[k] if k < len(reg2reg_pos) else None, start_idx)
            if j <= start_idx:
                continue
            if original_kind == "reg2reg":
                # equivalent only if later.src is the same physical source
                if not _same_phys_reg(s, meta.get("src")):
                    return True
            else:
                return True  # any later reg2reg differs

    # Later ARITH writes into dst (register destination)
    for a in getattr(g, "arith", []) or []:
        d = a.get("dst")
        if not _same_phys_reg(d, dst):
            continue
        j = _get_idx(a, default=start_idx)
        if j <= start_idx:
            continue
        if original_kind == "arith_reg":
            # arith_reg: treat ANY later write as different (no algebraic equivalence)
            return True
        else:
            return True  # later arith differs from memread/reg2reg originals

    # Later POP into dst
    pop_pos = getattr(g, "pop_pos", []) or []
    for k, r in enumerate(getattr(g, "pops", []) or []):
        if not _same_phys_reg(r, dst):
            continue
        j = _coerce_idx(pop_pos[k] if k < len(pop_pos) else None, start_idx)
        if j > start_idx:
            return True

    # Unclassified register writes (conservative)
    for entry in getattr(g, "unclassified_reg_writes", []) or []:
        try:
            i, _mn, dreg, _src = entry
        except Exception:
            continue
        if _same_phys_reg(dreg, dst) and isinstance(i, int) and i != -1 and i > start_idx:
            return True

    return False


def _earlier_overwrite_exists(g, upto_idx: int, reg: str) -> bool:
    """
    Return True if there is any write to `reg` at an instruction index strictly less than `upto_idx`.
    Treats AL/AH/AX/EAX as the same physical register (ignoring --exact-reg for this check).
    Writes considered:
      - reg2reg dst == reg (same physical register)
      - memread  dst == reg (same physical register)
      - arith    dst == reg (register destination only)
      - POP      into reg
    """
    # --- consider unclassified register writes ---
    for e in getattr(g, "unclassified_reg_writes", []) or []:
        if _uncls_get(e, "invalid", False):
            continue
        i = _uncls_get(e, "idx", -1)
        d = _uncls_get(e, "dst", None)
        if _same_phys_reg(d, reg) and isinstance(i, int) and i < upto_idx:
            return True

    if upto_idx is None or upto_idx < 0:
        return False

    # reg2reg writes
    reg2reg_pos = getattr(g, "reg2reg_pos", []) or []
    for i, (_s, d, _k) in enumerate(getattr(g, "reg2reg", []) or []):
        pos = _coerce_idx(reg2reg_pos[i] if i < len(reg2reg_pos) else None, -1)
        if _same_phys_reg(d, reg) and pos != -1 and pos < upto_idx:
            return True

    # memread dst
    memreads_pos = getattr(g, "memreads_pos", []) or []
    for i, mr in enumerate(getattr(g, "memreads", []) or []):
        pos = _coerce_idx(memreads_pos[i] if i < len(memreads_pos) else None, -1)
        if _same_phys_reg(getattr(mr, "dst", None), reg) and pos != -1 and pos < upto_idx:
            return True

    # arith dst (register destination only)
    for a in getattr(g, "arith", []) or []:
        pos = _get_idx(a, -1)
        if _same_phys_reg(a.get("dst"), reg) and pos != -1 and pos < upto_idx:
            return True

    # POP into reg
    pop_pos = getattr(g, "pop_pos", []) or []
    for j, r in enumerate(getattr(g, "pops", []) or []):
        p = _coerce_idx(pop_pos[j] if j < len(pop_pos) else None, -1)
        if _same_phys_reg(r, reg) and p != -1 and p < upto_idx:
            return True

    return False


# ------------------------------------------------------------
# Strict memory policy: only forbid absolute [0x...]
# ------------------------------------------------------------
def _all_mem_accesses_constrained(g, args) -> bool:
    """
    Simplified strict-mem (default Off):
      - Reject gadgets if they contain *any* absolute memory reference [0x...]
        in memreads, memwrites, or arith memory participants.
      - Allow base+disp forms freely.
    """
    # memreads / memwrites
    for mr in getattr(g, "memreads", []):
        if getattr(mr, "absolute", None) is not None:
            return False
    for mw in getattr(g, "memwrites", []):
        if getattr(mw, "absolute", None) is not None:
            return False
    # arith memory participants
    for a in getattr(g, "arith", []):
        dm = a.get("dst_mem")
        sm = a.get("src_mem")
        if dm and dm.get("abs") is not None:
            return False
        if sm and sm.get("abs") is not None:
            return False
    return True


# --- NEW: avoid-memref policy parsing and enforcement with skip list ---

def _parse_avoid_memref(spec: Optional[str]):
    """
    Parse the --avoid-memref pattern.
    Returns {"mode": "none"|"all"|"only"|"set", "regs": set[str]}.
      - none: disabled
      - all:  avoid all memrefs (subject to overrides/skip list)
      - set:  avoid memrefs whose base is in 'regs'         (e.g., "eax|ebx")
      - only: avoid memrefs whose base is NOT in 'regs'     (e.g., "!eax|ebx")
    """
    if not spec:
        return {"mode": "none", "regs": set()}
    s = spec.strip().lower()
    if s == "*":
        return {"mode": "all", "regs": set()}
    if s.startswith("!"):
        regs = {r.strip() for r in s[1:].split("|") if r.strip()}
        return {"mode": "only", "regs": regs}
    regs = {r.strip() for r in s.split("|") if r.strip()}
    return {"mode": "set", "regs": regs}


def _explicitly_requested_bases(args) -> set[str]:
    """
    Bases explicitly requested by other filters:
      - --memread  base=
      - --memwrite base=
      - --arith    src_base= / dst_base=
    """
    req = set()
    for key in ("memread_specs", "memwrite_specs"):
        for spec in getattr(args, key, []) or []:
            b = spec.get("base")
            if b:
                req.add(b.lower())
    for s in getattr(args, "arith", []) or []:
        kv = parse_kvlist(s)
        for k in ("src_base", "dst_base"):
            b = kv.get(k)
            if b:
                req.add(b.lower())
    return req

# Add this helper near _explicitly_requested_bases in ropfilter/filters.py

def _explicitly_requested_src_dst(args) -> Tuple[set[str], set[str]]:
    """
    Collect source/destination registers explicitly requested by user filters.
      - --memread  dst=<reg>
      - --memwrite src=<reg>
      - --arith    src=<reg> / dst=<reg>
    Returns: (srcs, dsts) as lowercase register names.
    """
    srcs: set[str] = set()
    dsts: set[str] = set()

    # memread: dst register is explicitly specified in filters
    for spec in (getattr(args, "memread_specs", []) or []):
        d = spec.get("dst")
        if d:
            dsts.add(d.lower())
        # be permissive if someone passes src= in memread filter
        s = spec.get("src")
        if s:
            srcs.add(s.lower())

    # memwrite: src register is explicitly specified in filters
    for spec in (getattr(args, "memwrite_specs", []) or []):
        s = spec.get("src")
        if s:
            srcs.add(s.lower())
        # be permissive if someone passes dst= in memwrite filter
        d = spec.get("dst")
        if d:
            dsts.add(d.lower())

    # arith: src / dst can be specified directly in the kv list
    for s in (getattr(args, "arith", []) or []):
        kv = parse_kvlist(s)
        sv = kv.get("src")
        if sv:
            srcs.add(sv.lower())
        dv = kv.get("dst")
        if dv:
            dsts.add(dv.lower())

    return srcs, dsts


def _memref_base_is_blocked(base: Optional[str], *, policy: dict) -> bool:
    """
    Decide if a memref with 'base' is blocked by policy.
    base=None => absolute
    """
    mode = policy["mode"]
    regs = policy["regs"]
    b = (base or "").lower()
    if mode == "none":
        return False
    if mode == "all":
        return True
    if mode == "set":
        return b in regs
    if mode == "only":
        return b not in regs
    return False


def _violates_avoid_memref_with_skip(g, args, skip_idxs: set[int]) -> bool:
    """
    Enforce --avoid-memref on all memref *except* those whose instruction idx is in skip_idxs.
    - Honors the previous behavior: in '*' mode, an explicitly requested_bases base in another filter
      (base=, src_base=, dst_base=) is allowed.
    """
    policy = _parse_avoid_memref(getattr(args, "avoid_memref", None))
    if policy["mode"] == "none":
        return False

    requested_bases = _explicitly_requested_bases(args) if policy["mode"] == "all" else set()
    requested_srcs, requested_dsts = _explicitly_requested_src_dst(args) if policy["mode"] == "all" else set(),set()

    def blocked(idx: Optional[int], base: Optional[str], is_abs: bool, *, kind: str = "other") -> bool:
        # Skip the instruction that satisfied the original filter(s)
        if isinstance(idx, int) and idx in skip_idxs:
            return False
        # Absolute references
        if is_abs:
            return policy["mode"] in ("all", "only")
        # In '*' mode, allow explicitly requested_bases base ONLY for memreads
        if policy["mode"] == "all" and base and (base.lower() in requested_bases or base.lower() in requested_srcs or base.lower() in requested_dsts):
            if kind == "read":
                return False  # exempt reads
            # for writes (and others), do NOT exempt
        return _memref_base_is_blocked(base, policy=policy)


    # memreads / memwrites
    for mr in getattr(g, "memreads", []):
        if blocked(getattr(mr, "idx", None), getattr(mr, "base", None), getattr(mr, "absolute", None) is not None, kind="read"):
            return True
    for mw in getattr(g, "memwrites", []):
        if blocked(getattr(mw, "idx", None), getattr(mw, "base", None), getattr(mw, "absolute", None) is not None, kind="write"):
            return True

    # arith memory operands
    for a in getattr(g, "arith", []):
        ai = a.get("idx")
        dm = a.get("dst_mem"); sm = a.get("src_mem")
        if dm and blocked(ai, dm.get("base"), dm.get("abs") is not None, kind="write"):
            return True
        if sm and blocked(ai, sm.get("base"), sm.get("abs") is not None, kind="read"):
            return True


    # call/jmp [mem]
    for d in getattr(g, "dispatch", []):
        if getattr(d, "target", None) == "mem":
            di = getattr(d, "idx", None)
            if blocked(di, getattr(d, "reg", None), getattr(d, "absolute", None) is not None, kind="other"):
                return True



    # v0.2.26 — apply avoid_memref to unclassified entries
    for e in getattr(g, "unclassified_reg_writes", []) or []:
        if _uncls_get(e, "invalid", False):
            continue
        ei = _uncls_get(e, "idx", None)

        if isinstance(ei, int) and ei in skip_idxs:
            continue
        # src_mem => read, dst_mem => write
        sm = _uncls_get(e, "src_mem", None)
        if sm:
            base = sm.get("base") if isinstance(sm, dict) else getattr(sm, "base", None)
            absaddr = sm.get("abs") if isinstance(sm, dict) else getattr(sm, "absolute", None)
            if blocked(ei, base, absaddr is not None, kind="read"):
                return True
        dm = _uncls_get(e, "dst_mem", None)
        if dm:
            base = dm.get("base") if isinstance(dm, dict) else getattr(dm, "base", None)
            absaddr = dm.get("abs") if isinstance(dm, dict) else getattr(dm, "absolute", None)
            if blocked(ei, base, absaddr is not None, kind="write"):
                return True


    return False

# ------------------------------------------------------------
# Main matcher
# ------------------------------------------------------------
def gadget_matches(g, args) -> bool:
    """
    Match a gadget against args. This version:
      1) First finds and records the instruction(s) that satisfy the user's positive filters.
      2) If --avoid-memref is present, it applies to all other instructions EXCEPT those which matched in step (1).
    """
    # -----------------------------
    # Early address / shape checks
    # -----------------------------
    if args.addr_no_bytes and addr_has_bytes(g.address, args.addr_no_bytes) > 0:
        return False
    if args.max_instr is not None and g.instr_count > args.max_instr:
        return False
    if args.ret_only and (g.ret_imm is None or g.ret_imm != 0):
        return False
    if args.retn is not None and (g.ret_imm is None or g.ret_imm > args.retn):
        return False
    if args.max_stack_delta is not None and (g.stack_delta is None or g.stack_delta > args.max_stack_delta):
        return False
    if getattr(args, "avoid_clobber", None) and any(r in g.clobbers for r in args.avoid_clobber):
        return False
    if getattr(args, "require_writes", None) and not all(r in g.clobbers for r in args.require_writes):
        return False
    if getattr(args, "protect_stack", None) and g.excessive_pushes:
        return False
    #set_exact_reg_mode(getattr(args, "exact_reg", False))
    #print(f"get_exact_reg_mode: {get_exact_reg_mode()}")
        

    # --------------------------------------------
    # Strict memory policy (keep existing behavior)
    # --------------------------------------------
    if getattr(args, "strict_mem", False):
        ok = _all_mem_accesses_constrained(g, args)
        if not ok:
            if getattr(args, "debug", False):
                print(f"[DEBUG] drop 0x{g.address:08x} due to strict-mem (absolute mem ref)")
            return False

    # ============================================================
    # NEW: Track which instruction(s) satisfied positive filters
    # ============================================================
    matched_instr_idxs: set[int] = set()     # indices in the gadget's instruction stream
    def _rec_idx_from_pos(seq_pos_list, pos_idx):
        """Helper for reg2reg: use recorded positions when present."""
        try:
            if seq_pos_list is not None and pos_idx < len(seq_pos_list):
                v = seq_pos_list[pos_idx]
                if isinstance(v, int):
                    matched_instr_idxs.add(v)
        except Exception:
            pass

    # ---------------------------------------
    # Register transfers (single-step) checks
    # ---------------------------------------
    for src, dst in getattr(args, "reg2reg_specs", []):
        ok = False
        reg2reg_pos = getattr(g, "reg2reg_pos", [])
        for idx_tuple, (s, d, _) in enumerate(getattr(g, "reg2reg", [])):
            if not (reg_match(s, src) and reg_match(d, dst)):
                continue

            # Stability check (order-aware)
            if getattr(args, "stable_dst", False):
                start_i = _coerce_idx(reg2reg_pos[idx_tuple] if idx_tuple < len(reg2reg_pos) else None, -1)
                if _later_overwrite_is_different(g, start_i, d, "reg2reg", {"src": s}):
                    continue
            # --stable-src: no earlier overwrite of the source
            if getattr(args, "stable_src", False):
                match_idx = _coerce_idx(reg2reg_pos[idx_tuple] if idx_tuple < len(reg2reg_pos) else None, -1)
                if _earlier_overwrite_exists(g, match_idx, s):
                    continue

            # NEW: record the matched instruction idx (if we have it)
            _rec_idx_from_pos(reg2reg_pos, idx_tuple)
            ok = True
            break
        if not ok:
            return False

    # ---------------
    # Memory reads
    # ---------------
    for spec in getattr(args, "memread_specs", []):
        ok = False
        want_dst_pat = spec.get("dst")
        want_base_pat = spec.get("base")
        absaddr = int(spec["abs"], 16) if "abs" in spec else None

        for k, mr in enumerate(getattr(g, "memreads", [])):
            if not reg_match(mr.dst, want_dst_pat):
                continue

            if absaddr is not None:
                if mr.absolute == absaddr:
                    # Stability check
                    if getattr(args, "stable_dst", False):
                        if _later_overwrite_is_different(
                            g,
                            _get_idx(mr, -1),
                            mr.dst,
                            "memread",
                            {"base": mr.base, "abs": mr.absolute, "disp": mr.disp, "op": getattr(mr, "op", None)},
                        ):
                            continue
                    # NEW: record index
                    matched_instr_idxs.add(_get_idx(mr, k))
                    ok = True
                    break
                else:
                    continue

            if not reg_match(mr.base, want_base_pat):
                continue
            if not mem_spec_op_ok(mr, spec):
                continue

            # displacement filters
            disp_eq = _as_int_or_none(spec.get("disp"))
            disp_gt = _as_int_or_none(spec.get("disp>"))
            disp_ge = _as_int_or_none(spec.get("disp>="))
            disp_lt = _as_int_or_none(spec.get("disp<"))
            disp_le = _as_int_or_none(spec.get("disp<="))
            if any(x is not None for x in (disp_eq, disp_gt, disp_ge, disp_lt, disp_le)):
                if mr.disp is None:
                    continue
                if disp_eq is not None and mr.disp != disp_eq:
                    continue
                if disp_gt is not None and not (mr.disp > disp_gt):
                    continue
                if disp_ge is not None and not (mr.disp >= disp_ge):
                    continue
                if disp_lt is not None and not (mr.disp < disp_lt):
                    continue
                if disp_le is not None and not (mr.disp <= disp_le):
                    continue

            # Stability check: original value is memory load
            if getattr(args, "stable_dst", False):
                if _later_overwrite_is_different(
                    g,
                    _get_idx(mr, -1),
                    mr.dst,
                    "memread",
                    {"base": mr.base, "abs": mr.absolute, "disp": mr.disp, "op": getattr(mr, "op", None)},
                ):
                    continue

            # NEW: record index
            matched_instr_idxs.add(_get_idx(mr, k))
            ok = True
            break

        if not ok:
            return False

    # ----------------------------------------
    # Arithmetic / logical operations (register + memory forms)
    # ----------------------------------------
    for spec in getattr(args, "arith", []):
        kv = parse_kvlist(spec)
        ok = False
        for i, a in enumerate(getattr(g, "arith", [])):
            # op filter (supports alternation and negation, implemented in _op_match earlier in file)
            if not _op_match(a.get("op"), kv.get("op")):
                continue

            # reg dst/src filters
            if "dst" in kv and not reg_match(a.get("dst"), kv["dst"]):
                continue
            if "src" in kv and not reg_match(a.get("src"), kv["src"]):
                continue
            if "imm" in kv:
                if "imm" not in a: continue
                if _as_int_or_none(kv['imm']) != a["imm"]: continue

            # dst_mem filters
            if "dst_base" in kv or "dst_abs" in kv:
                dm = a.get("dst_mem")
                if not dm:
                    continue
                if "dst_base" in kv and not reg_match(dm.get("base"), kv["dst_base"]):
                    continue
                if "dst_abs" in kv:
                    try:
                        v = int(kv["dst_abs"], 0)
                    except Exception:
                        continue
                    if dm.get("abs") != v:
                        continue
                # displacement filters for dst_mem
                dd_eq = _as_int_or_none(kv.get("dst_disp"))
                dd_gt = _as_int_or_none(kv.get("dst_disp>"))
                dd_ge = _as_int_or_none(kv.get("dst_disp>="))
                dd_lt = _as_int_or_none(kv.get("dst_disp<"))
                dd_le = _as_int_or_none(kv.get("dst_disp<="))
                if any(x is not None for x in (dd_eq, dd_gt, dd_ge, dd_lt, dd_le)):
                    if dm.get("disp") is None:
                        continue
                    dval = dm.get("disp")
                    if dd_eq is not None and dval != dd_eq:
                        continue
                    if dd_gt is not None and not (dval > dd_gt):
                        continue
                    if dd_ge is not None and not (dval >= dd_ge):
                        continue
                    if dd_lt is not None and not (dval < dd_lt):
                        continue
                    if dd_le is not None and not (dval <= dd_le):
                        continue

            # src_mem filters
            if "src_base" in kv or "src_abs" in kv:
                sm = a.get("src_mem")
                if not sm:
                    continue
                if "src_base" in kv and not reg_match(sm.get("base"), kv["src_base"]):
                    continue
                if "src_abs" in kv:
                    try:
                        v = int(kv["src_abs"], 0)
                    except Exception:
                        continue
                    if sm.get("abs") != v:
                        continue
                # displacement filters for src_mem
                sd_eq = _as_int_or_none(kv.get("src_disp"))
                sd_gt = _as_int_or_none(kv.get("src_disp>"))
                sd_ge = _as_int_or_none(kv.get("src_disp>="))
                sd_lt = _as_int_or_none(kv.get("src_disp<"))
                sd_le = _as_int_or_none(kv.get("src_disp<="))
                if any(x is not None for x in (sd_eq, sd_gt, sd_ge, sd_lt, sd_le)):
                    if sm.get("disp") is None:
                        continue
                    sval = sm.get("disp")
                    if sd_eq is not None and sval != sd_eq:
                        continue
                    if sd_gt is not None and not (sval > sd_gt):
                        continue
                    if sd_ge is not None and not (sval >= sd_ge):
                        continue
                    if sd_lt is not None and not (sval < sd_lt):
                        continue
                    if sd_le is not None and not (sval <= sd_le):
                        continue


            # Stability check for arith with register destination
            if getattr(args, "stable_dst", False) and a.get("dst"):
                if _later_overwrite_is_different(
                    g,
                    _get_idx(a, i),
                    a.get("dst"),
                    "arith_reg",
                    {"op": a.get("op"), "src": a.get("src")},
                ):
                    continue

            # --stable-src for ARITH (register source only; src_mem is memory)
            if getattr(args, "stable_src", False):
                src_reg = a.get("src") or a.get("src_reg")
                if src_reg:
                    match_idx = _get_idx(a, i)
                    if _earlier_overwrite_exists(g, match_idx, src_reg):
                        continue


            # NEW: record the arith op's idx if present
            matched_instr_idxs.add(_get_idx(a, i))
            ok = True
            break

        if not ok:
            return False

    # ---------------
    # Memory writes
    # ---------------
    for spec in getattr(args, "memwrite_specs", []):
        ok = False
        want_src_pat = spec.get("src")
        want_base_pat = spec.get("base")
        absaddr = int(spec["abs"], 16) if "abs" in spec else None

        for k, mw in enumerate(getattr(g, "memwrites", [])):
            if not reg_match(mw.src, want_src_pat):
                continue

            if absaddr is not None:
                if mw.absolute == absaddr:
                    # NEW: record index
                    matched_instr_idxs.add(_get_idx(mw, k))
                    ok = True
                    break
                else:
                    continue

            if not reg_match(mw.base, want_base_pat):
                continue
            if not mem_spec_op_ok(mw, spec):
                continue

            # displacement filters
            disp_eq = _as_int_or_none(spec.get("disp"))
            disp_gt = _as_int_or_none(spec.get("disp>"))
            disp_ge = _as_int_or_none(spec.get("disp>="))
            disp_lt = _as_int_or_none(spec.get("disp<"))
            disp_le = _as_int_or_none(spec.get("disp<="))
            if any(x is not None for x in (disp_eq, disp_gt, disp_ge, disp_lt, disp_le)):
                if mw.disp is None:
                    continue
                if disp_eq is not None and mw.disp != disp_eq:
                    continue
                if disp_gt is not None and not (mw.disp > disp_gt):
                    continue
                if disp_ge is not None and not (mw.disp >= disp_ge):
                    continue
                if disp_lt is not None and not (mw.disp < disp_lt):
                    continue
                if disp_le is not None and not (mw.disp <= disp_le):

                    continue
            # --stable-src for MEMWRITE: check earlier overwrite of the register src
            if getattr(args, "stable_src", False):
                match_idx = _get_idx(mw, k)
                src_reg = getattr(mw, "src", None)
                if src_reg and _earlier_overwrite_exists(g, match_idx, src_reg):
                    continue

            # NEW: record index
            matched_instr_idxs.add(_get_idx(mw, k))
            ok = True
            break

        if not ok:
            return False

    # ---------------------------------------------
    # Pivot / sequences / dispatch / clobber checks
    # ---------------------------------------------
    if getattr(args, "pivot", False):
        if not g.pivot:
            return False
        if getattr(args, "pivot_kind", None) and not any(p.kind == args.pivot_kind for p in g.pivot):
            return False
        if getattr(args, "pivot_reg", None) and not any(p.reg == args.pivot_reg for p in g.pivot):
            return False
        if getattr(args, "pivot_imm", None) is not None and not any(p.imm == args.pivot_imm for p in g.pivot):
            return False

    if getattr(args, "pop_seq", None):
        j = 0
        for r in g.pops:
            if j < len(args.pop_seq) and r == args.pop_seq[j]:
                j += 1
        if j < len(args.pop_seq):
            return False

    # call/jmp filters (record idx if they match)
    if getattr(args, "call_reg", None) or getattr(args, "call_abs", None) is not None or getattr(args, "call_mem", None):
        def okd(d) -> bool:
            if d.kind not in ("call", "jmp"):
                return False
            if getattr(args, "call_reg", None) and d.target == "reg" and d.reg == args.call_reg:
                matched_instr_idxs.add(_get_idx(d, -1))
                return True
            if getattr(args, "call_abs", None) is not None and d.target == "abs" and d.absolute == args.call_abs:
                matched_instr_idxs.add(_get_idx(d, -1))
                return True
            if getattr(args, "call_mem", None) and d.target == "mem" and d.reg == args.call_mem:
                matched_instr_idxs.add(_get_idx(d, -1))
                return True
            return False

        if not any(okd(d) for d in g.dispatch):
            return False



    # ========================================================
    # NEW: Apply --avoid-memref to all non-matching instructions
    # ========================================================
    # --- NEW: enforce --avoid-memref on *other* instructions only ---
    if _violates_avoid_memref_with_skip(g, args, matched_instr_idxs):
        return False

    return True



# --- auto-wrap functions for debug trace ---

#_same_phys_reg = _trace(_same_phys_reg)
#_uncls_get = _trace(_uncls_get)
#_as_int_or_none = _trace(_as_int_or_none)
#_op_match = _trace(_op_match)
#_coerce_idx = _trace(_coerce_idx)
#_get_idx = _trace(_get_idx)
#_later_overwrite_is_different = _trace(_later_overwrite_is_different)
#_earlier_overwrite_exists = _trace(_earlier_overwrite_exists)
#_all_mem_accesses_constrained = _trace(_all_mem_accesses_constrained)
#_parse_avoid_memref = _trace(_parse_avoid_memref)
#_explicitly_requested_bases = _trace(_explicitly_requested_bases)
#_memref_base_is_blocked = _trace(_memref_base_is_blocked)
#_violates_avoid_memref_with_skip = _trace(_violates_avoid_memref_with_skip)
#gadget_matches = _trace(gadget_matches)

# --- end auto-wrap ---
