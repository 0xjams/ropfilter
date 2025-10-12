# ropfilter/chain.py
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

def _safe(val, _seen=None, _param=None):
    if _seen is None:
        _seen = set()
    try:
        oid = id(val)
        if oid in _seen:
            return "<recursion>"
        _seen.add(oid)

        # Primitives
        if isinstance(val, (int, float, bool)) or val is None:
            return val
        if isinstance(val, str):
            return val

        # Bytes-like → full hex
        if isinstance(val, (bytes, bytearray, memoryview)):
            return bytes(val).hex()

        # Sequences / sets
        if isinstance(val, (list, tuple, set, frozenset)):
            seq = list(val)

            # Special-case ONLY the param literally named "gadgets":
            # If it looks like a list of Gadget-like objects, serialize only the first.
            if _param == "gadgets" and len(seq) > 0:
                first = seq[0]
                if getattr(first, "address", None) is not None and getattr(first, "text", None) is not None:
                    return {
                        "len": len(seq),
                        "first": _safe(first, _seen, _param="gadget")
                    }

            # Otherwise, serialize the entire sequence
            out = [_safe(x, _seen, _param=_param) for x in seq]
            return out if not isinstance(val, tuple) else tuple(out)

        # Dicts (full)
        if isinstance(val, dict):
            return {str(k): _safe(v, _seen, _param=_param) for k, v in val.items()}

        # Special-case Gadget-like objects
        addr = getattr(val, "address", None)
        text = getattr(val, "text", None)
        if addr is not None and text is not None:
            try:
                hx = hex(addr)
            except Exception:
                hx = addr
            return {"Gadget": hx, "text": text}

        # argparse.Namespace / SimpleNamespace / ad-hoc objects like T()
        try:
            attrs = vars(val)  # may raise if no __dict__
        except Exception:
            attrs = None
        if attrs is not None:
            return {"type": type(val).__name__, "attrs": {str(k): _safe(v, _seen, _param=k) for k, v in attrs.items()}}

        # Fallback: repr
        return repr(val)
    except Exception as e:
        return f"<unserializable: {e}>"
    finally:
        try:
            _seen.discard(id(val))
        except Exception:
            pass
def _trace(func):
    import inspect
    name = f"{__name__}.{func.__name__}"
    sig = None
    try:
        sig = getattr(func, "__signature__", None) or inspect.signature(func)
    except Exception:
        pass

    def wrapper(*args, **kwargs):
        lg = _get_logger()

        # Build name-aware args so we can detect the 'gadgets' param specifically
        param_names = []
        if sig is not None:
            try:
                param_names = list(sig.parameters.keys())
            except Exception:
                param_names = []

        ser_args = []
        for i, a in enumerate(args):
            pname = param_names[i] if i < len(param_names) else None
            ser_args.append(_safe(a, _param=pname))

        ser_kwargs = {k: _safe(v, _param=k) for k, v in kwargs.items()}

        try:
            lg.emit("enter", func=name, args=ser_args, kwargs=ser_kwargs)
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


from collections import defaultdict, deque
from typing import List, Dict, Tuple
from .models import Gadget
from .constants import REGS
from .utils import canon_reg, parse_kvlist, get_disp_key, set_exact_reg_mode
# chain.py — extend imports
from .ranking import ret_rank_of, memread_disp_rank, memwrite_disp_rank


from types import SimpleNamespace
from .filters import gadget_matches


def _reg2reg_lea_disp_rank(g: Gadget, j: int, src_norm: str, dst_norm: str) -> int:
    """
    Approximate displacement rank for a reg2reg hop when it originated from LEA.
    We avoid touching classify.py by reading the matching arith entry (op='lea')
    that has the same dst and base (src), nearest in index to the reg2reg site.
    Buckets (lower is better): 0 (0), 1 (<=8), 2 (<=32), 3 (<=128), 4 (else).
    """
    try:
        _s, _d, k = g.reg2reg[j]
    except Exception:
        return 0
    if k != "lea":
        return 0

    pos_list = getattr(g, "reg2reg_pos", []) or []
    anchor = pos_list[j] if j < len(pos_list) else None

    best = None  # (delta, abs_disp)
    for a in getattr(g, "arith", []) or []:
        if not isinstance(a, dict):
            continue
        if a.get("op") != "lea":
            continue
        if canon_reg(a.get("dst") or "") != dst_norm:
            continue
        if canon_reg(a.get("base") or "") != src_norm:
            continue
        disp = a.get("disp", 0) or 0
        ai = a.get("idx", None)
        delta = abs((ai if isinstance(ai, int) else 0) - (anchor if isinstance(anchor, int) else 0))
        cand = (delta, abs(int(disp)))
        if best is None or cand < best:
            best = cand

    d = 0 if best is None else best[1]
    if d == 0:   return 0
    if d <= 8:   return 1
    if d <= 32:  return 2
    if d <= 128: return 3
    return 4


def _hop_args(base_args, *, reg2reg_specs=None, memread_specs=None, memwrite_specs=None):
    """
    Build a minimal args object for a single hop that preserves global policy flags.
    This ensures --avoid-memref/--strict-mem/--stable-*/--avoid-clobber/etc. are enforced per hop.
    """
    return SimpleNamespace(
        # global filters we should preserve
        addr_no_bytes=getattr(base_args, "addr_no_bytes", None),
        max_instr=getattr(base_args, "max_instr", None),
        ret_only=getattr(base_args, "ret_only", False),
        retn=getattr(base_args, "retn", None),
        max_stack_delta=getattr(base_args, "max_stack_delta", None),
        avoid_memref=getattr(base_args, "avoid_memref", None),
        strict_mem=getattr(base_args, "strict_mem", False),
        stable_dst=getattr(base_args, "stable_dst", False),
        stable_src=getattr(base_args, "stable_src", False),
        avoid_clobber=getattr(base_args, "avoid_clobber", None),
        require_writes=getattr(base_args, "require_writes", None),
        debug=getattr(base_args, "debug", False),
        protect_stack=getattr(base_args, "protect_stack", False),

        # per-hop positive spec
        reg2reg_specs=reg2reg_specs or [],
        memread_specs=memread_specs or [],
        memwrite_specs=memwrite_specs or [],

        # keep others empty for this micro-match
        arith=[],
        pop_seq=None,
        call_abs=None, call_mem=None, jmp_abs=None, jmp_mem=None,
        pivot=False, pivot_kind=None, pivot_reg=None, pivot_imm=None,
    )

def _copy_chain_args(base_args, **overrides):
    """
    Create a trimmed args object for per-hop matching during chaining.
    We preserve global behavioral flags so chain hops obey the same rules:
      - stable_dst, stable_src
      - strict_mem
      - avoid_memref
      - avoid_clobber
      - addr_no_bytes / max-instr / ret-only / retn / max-stack-delta (if present)
    And inject a micro-spec (e.g., reg2reg_specs, memread_specs, memwrite_specs) per hop.
    """
    keep = {
        "stable_dst", "stable_src",
        "strict_mem",
        "avoid_memref",
        "avoid_clobber",
        "addr_no_bytes",
        "max_instr",
        "ret_only",
        "retn",
        "max_stack_delta",
    }
    d = {k: getattr(base_args, k) for k in keep if hasattr(base_args, k)}
    d.update(overrides)
    # Ensure lists default to [] so gadget_matches downstream is happy.
    d.setdefault("reg2reg_specs", [])
    d.setdefault("memread_specs", [])
    d.setdefault("memwrite_specs", [])
    # For arithmetic-based hops (rare in chaining, but safe default)
    d.setdefault("arith", [])
    return SimpleNamespace(**d)

def _reg_protected_set(dst=None, src=None, extra=None):
    """
    Registers we must not clobber across a hop. Always protect ESP implicitly.
    """
    s = {"esp"}
    if dst: s.add(canon_reg(dst))
    if src: s.add(canon_reg(src))
    if extra:
        s |= {canon_reg(r) for r in extra}
    return s

def _clobbers_any(g, regs: set[str]) -> bool:
    """
    Returns True if gadget 'g' is known to clobber any protected register in 'regs'.
    We consult g.clobbers and also consider obvious writers (pops, reg2reg dsts, arith dsts).
    """
    # classifiers already put many regs in g.clobbers — honor them
    for r in getattr(g, "clobbers", []):
        if canon_reg(r) in regs:
            return True

    # Conservative extras
    for r in getattr(g, "pops", []):
        if canon_reg(r) in regs:
            return True
    for (src, dst, _kind) in getattr(g, "reg2reg", []):
        if canon_reg(dst) in regs:
            return True
    for a in getattr(g, "arith", []):
        d = a.get("dst")
        if d and isinstance(d, str) and canon_reg(d) in regs:
            return True
        # If arithmetic writes memory, not a register, it doesn't clobber protected regs by itself.

    return False

def _avoid_memref_blocks_intermediate(g, args) -> bool:
    """
    We still call gadget_matches() to fully evaluate avoid-memref logic; this helper exists
    in case you ever want an early fast-path. For now, keep it permissive and let
    gadget_matches() be the source of truth. Returning False here means 'do not early-block'.
    """
    return False  # defer to gadget_matches()


def is_clean_ret(g: Gadget) -> bool:
    # Chain gadgets must return; accept 'ret' and 'retn imm'
    return g.ret_imm is not None


def mem_op_pref(mem) -> int:
    # prefer [base], then [base+disp], then [abs] — lower is better
    if mem.absolute is not None: return 2
    if mem.disp is None: return 0
    return 1

def build_transfer_edges(gadgets: List[Gadget], args) -> Dict[str, List[Tuple[str, Gadget]]]:
    """
    Build a directed graph of register transfers (src -> dst) but ONLY include edges
    realized by gadgets that pass the full policy via gadget_matches() for that hop.
    This makes reg chaining honor: --avoid-memref, --strict-mem, --stable-*, --avoid-clobber, --exact-reg.
    Ranked per (S->D): (ret_rank, lea_disp_rank, instr_count, address) ascending.
    """
    # collect then sort per-hop
    pool = defaultdict(list)  # (S,D) -> [(key, gadget)]
    for g in gadgets:
        # chains must use returning gadgets (ret or retn)
        if g.ret_imm is None:
            continue
        for (s, d, k) in getattr(g, "reg2reg", []):
            S, D = canon_reg(s), canon_reg(d)
            if not S or not D:
                continue
            hop_args = _hop_args(args, reg2reg_specs=[(S, D)])
            if not gadget_matches(g, hop_args):
                continue
            # index of this reg2reg entry (for LEA disp lookup)
            j = None
            for jj, (ss, dd, kk) in enumerate(getattr(g, "reg2reg", []) or []):
                if canon_reg(ss) == S and canon_reg(dd) == D and kk == k:
                    j = jj
                    break
            lea_rank = _reg2reg_lea_disp_rank(g, j or 0, S, D)
            key = (ret_rank_of(g), lea_rank, g.instr_count or 0, g.address)
            pool[(S, D)].append((key, g))

    edges = defaultdict(list)
    for (S, D), items in pool.items():
        items.sort(key=lambda x: x[0])  # best-first
        for _key, g in items:
            edges[S].append((D, g))
    return edges



def find_reg_chain(src: str, dst: str, gadgets: List[Gadget], args) -> List[List[Gadget]]:
    """
    BFS over the reg-transfer graph built with full-policy validation.
    """
    src = canon_reg(src)
    dst = canon_reg(dst)
    set_exact_reg_mode(bool(getattr(args, "exact_reg", False)))

    if not src or not dst:
        return []

    edges = build_transfer_edges(gadgets, args)
    if src not in edges:
        return []

    allow = set(args.chain_allow) if getattr(args, "chain_allow", None) else set(REGS)
    if not getattr(args, "chain_allow", None) and "esp" in allow:
        allow.remove("esp")
    allow.add(src); allow.add(dst)

    results: list[list[Gadget]] = []
    q = deque([(src, [])])
    visited = {src}
    max_steps = getattr(args, "chain_max_steps", 3)
    limit = getattr(args, "chain_limit", 10)

    while q:
        cur, path = q.popleft()
        if len(path) >= max_steps:
            continue
        for (nxt, gad) in edges.get(cur, []):
            if nxt not in allow:
                continue
            new_path = path + [gad]
            if nxt == dst:
                results.append(new_path)
                if len(results) >= limit:
                    return results
            if nxt not in visited:
                visited.add(nxt)
                q.append((nxt, new_path))
    return results



def find_memread_chain(dst, base, gadgets: List[Gadget], args) -> List[List[Gadget]]:
    """
    Build chains for: mov dst, [base + disp?]
    Try direct memread into dst first; otherwise memread into T then reg2reg T->dst.
    Every hop is validated with gadget_matches() so flags are honored.
    """
    D = canon_reg(dst) if dst else None
    B = canon_reg(base) if base else None
    set_exact_reg_mode(bool(getattr(args, "exact_reg", False)))


    allow = set(args.chain_allow) if getattr(args, "chain_allow", None) else set(REGS)
    if not getattr(args, "chain_allow", None) and "esp" in allow:
        allow.remove("esp")
    if D: allow.add(D)
    memread_specs = args.memread_specs[0]

    # collect & rank memread candidates by preference
    memread_cands: list[tuple[int, Gadget, object]] = []
    for g in gadgets:
        if not is_clean_ret(g):
            continue
        for mr in getattr(g, "memreads", []):
            if B and canon_reg(getattr(mr, "base", None) or "") != B:
                continue
            spec = {"base": B} if B else {}
            disp_key =  get_disp_key(memread_specs)
            if disp_key:
                disp_value = memread_specs[disp_key]
                spec[disp_key] = disp_value
            if "op" in memread_specs:
                spec["op"] = memread_specs["op"]

            hop_args = _hop_args(args, memread_specs=[spec])
            if not gadget_matches(g, hop_args):
                continue
            memread_cands.append((mem_op_pref(mr), g, mr))

    memread_cands.sort(key=lambda t: (
        t[0],
        memread_disp_rank(t[1], [{'base': B}] if B else []),
        ret_rank_of(t[1]),
        t[1].instr_count or 0,
        t[1].address
    ))


    results: list[list[Gadget]] = []
    limit = getattr(args, "chain_limit", 10)

    for _, g1, mr in memread_cands:
        T = canon_reg(getattr(mr, "dst", None) or "")
        if not T or T not in allow:
            continue

        if D and T == D:
            results.append([g1])
            if len(results) >= limit:
                return results
            continue

        if D:
            hop2_args = _hop_args(args, reg2reg_specs=[(T, D)])
            candidates = []
            for g2 in gadgets:
                for j, (s, d, k) in enumerate(getattr(g2, "reg2reg", []) or []):
                    if canon_reg(s) == T and canon_reg(d) == D and gadget_matches(g2, hop2_args):
                        lea_rank = _reg2reg_lea_disp_rank(g2, j, T, D)
                        key = (ret_rank_of(g2), lea_rank, g2.instr_count or 0, g2.address)
                        candidates.append((key, g2))
                        break
            if candidates:
                candidates.sort(key=lambda x: x[0])
                best_g2 = candidates[0][1]
                results.append([g1, best_g2])
                if len(results) >= limit:
                    return results

        else:
            results.append([g1])
            if len(results) >= limit:
                return results

    return results



def find_memwrite_chain(src, base, gadgets: List[Gadget], args) -> List[List[Gadget]]:
    """
    Build chains for: mov [base + disp?], src
    Prefer direct memwrite from src; otherwise reg2reg src->T then memwrite [base],T.
    All hops pass gadget_matches().
    """
    S = canon_reg(src) if src else None
    B = canon_reg(base) if base else None
    set_exact_reg_mode(bool(getattr(args, "exact_reg", False)))

    memwrite_specs = args.memwrite_specs[0]

    allow = set(args.chain_allow) if getattr(args, "chain_allow", None) else set(REGS)
    if not getattr(args, "chain_allow", None) and "esp" in allow:
        allow.remove("esp")
    if S: allow.add(S)

    # group memwrites by their source register
    mw_by_src: Dict[str, list[tuple[int, Gadget, object]]] = defaultdict(list)

    for g in gadgets:
        if not is_clean_ret(g):
            continue
        for mw in getattr(g, "memwrites", []):
            if B and canon_reg(getattr(mw, "base", None) or "") != B:
                continue
            spec = {"base": B} if B else {}
            disp_key =  get_disp_key(memwrite_specs)
            if disp_key:
                disp_value = memwrite_specs[disp_key]
                spec[disp_key] = disp_value
            if "op" in memwrite_specs:
                spec["op"] = memwrite_specs["op"]

            hop_args = _hop_args(args, memwrite_specs=[spec])
            if not gadget_matches(g, hop_args):
                continue
            T = canon_reg(getattr(mw, "src", None) or "")
            if not T:
                continue
            mw_by_src[T].append((mem_op_pref(mw), g, mw))

    for T in mw_by_src:
        # Preserve original preference (base->disp->abs) via t[0],
        # then refine with memwrite_disp_rank and return kind, then length/address.
        mw_by_src[T].sort(
            key=lambda t: (
                t[0],
                memwrite_disp_rank(t[1], [{'base': B, 'src': T}] if B else [{'src': T}]),
                ret_rank_of(t[1]),
                t[1].instr_count or 0,
                t[1].address
            )
        )

    results: list[list[Gadget]] = []
    limit = getattr(args, "chain_limit", 10)

    # direct src-> [base]
    if S in mw_by_src:
        results.append([mw_by_src[S][0][1]])
        if len(results) >= limit:
            return results

    # otherwise src->T ; [base]<=T
    for T, lst in mw_by_src.items():
        if S and T != S:
            hop1_args = _hop_args(args, reg2reg_specs=[(S, T)])
            candidates = []
            for g1 in gadgets:
                for j, (s, d, k) in enumerate(getattr(g1, "reg2reg", []) or []):
                    if canon_reg(s) == S and canon_reg(d) == T and gadget_matches(g1, hop1_args):
                        lea_rank = _reg2reg_lea_disp_rank(g1, j, S, T)
                        key = (ret_rank_of(g1), lea_rank, g1.instr_count or 0, g1.address)
                        candidates.append((key, g1))
                        break
            if not candidates:
                continue
            candidates.sort(key=lambda x: x[0])
            best_g1 = candidates[0][1]
            results.append([best_g1, lst[0][1]])
            if len(results) >= limit:
                return results


    return results



def find_arith_chain(kv: dict, gadgets: List[Gadget], args) -> List[List[Gadget]]:
    """
    Build short chains that satisfy an ARITH constraint when a single gadget is not available.

    Supported scenarios (best-first):
      1) Direct ARITH gadget that matches `kv` → [[g]]
      2) Reg/Reg: If op D,S not available, allow reg2reg shims:
           - S -> T ; (op D,T)
           - D->T ; (op T,S) ; T->D
           - [CANCELED] (op T,S) ; T -> D
           - [CANCELED] S -> T ; (op U,T) ; U -> D
      3) Src memory (kv has src_* fields): read value to T then do (op D,T).
      4) Dst memory (kv has dst_* fields): read [mem] to T ; (op T,S) ; write T back.

    Ranking: shorter chains first; then sum of ret_rank; then total instr_count; then last address.
    All hops (memread/memwrite/reg2reg/arith) are validated with gadget_matches() using a per-hop
    micro-args that inherit global policy flags (--avoid-memref, --strict-mem, --stable-*, etc.).
    """
    limit = max(1, getattr(args, "chain_limit", 10))
    max_steps = max(2, getattr(args, "chain_max_steps", 3))
    set_exact_reg_mode(bool(getattr(args, "exact_reg", False)))


    # Extract core fields
    op_pat   = kv.get("op")
    D        = canon_reg(kv.get("dst")) if kv.get("dst") else None
    S        = canon_reg(kv.get("src")) if kv.get("src") else None

    # Memory specs (presence implies memory operand expected)
    src_base = canon_reg(kv.get("src_base")) if kv.get("src_base") else None
    dst_base = canon_reg(kv.get("dst_base")) if kv.get("dst_base") else None
    src_abs  = kv.get("src_abs")
    dst_abs  = kv.get("dst_abs")

    def _is_src_mem():
        return (src_base is not None) or (src_abs is not None)
    def _is_dst_mem():
        return (dst_base is not None) or (dst_abs is not None)

    # Helpers
    def _rank_path(path: list[Gadget]) -> tuple:
        return (
            len(path),
            sum(ret_rank_of(g) for g in path),
            sum((g.instr_count or 0) for g in path),
            path[-1].address if path else 0,
        )

    # Normalize incoming spec(s): accept dict | str | list[dict|str]
    def _norm_spec(x) -> dict:
        if isinstance(x, dict):
            return dict(x)
        if isinstance(x, str):
            try:
                return parse_kvlist(x) or {}
            except Exception:
                return {}
        return {}

    # If the caller passed a list (e.g., args.arith_specs), explode and aggregate
    if isinstance(kv, (list, tuple)):
        agg_paths: list[list[Gadget]] = []
        for item in kv:
            item_kv = _norm_spec(item)
            if not item_kv:
                continue
            agg_paths.extend(find_arith_chain(item_kv, gadgets, args))
        # Rank + truncate combined results
        agg_paths = sorted(agg_paths, key=lambda p: (
            len(p),
            sum(ret_rank_of(g) for g in p),
            sum((g.instr_count or 0) for g in p),
            p[-1].address if p else 0,
        ))[:limit]
        return agg_paths

    # Ensure kv is dict from here on
    kv = _norm_spec(kv)

    def _kv_to_str(d: dict) -> str:
        parts = []
        for k, v in d.items():
            if v is None:
                continue
            if isinstance(v, int):
                parts.append(f"{k}={hex(v)}")
            else:
                parts.append(f"{k}={v}")
        return ",".join(parts)

    def _arith_match_args(extra_kv: dict | None = None):
        spec = dict(kv)
        if extra_kv:
            spec.update(extra_kv)
        # IMPORTANT: gadget_matches expects kvlist strings for arith specs
        spec_str = _kv_to_str(spec)
        return _copy_chain_args(args, arith=[spec_str])


    allow = set(getattr(args, "chain_allow", []) or REGS)
    if not getattr(args, "chain_allow", None) and "esp" in allow:
        allow.remove("esp")
    if D: allow.add(D)
    if S: allow.add(S)

    results: list[list[Gadget]] = []

    # ----------------
    # Phase 1: direct
    # ----------------
    best_direct = []
    for g in gadgets:
        if not is_clean_ret(g):
            continue
        #print(_arith_match_args())
        #exit()
        if gadget_matches(g, _arith_match_args()):
            #print(g)
            #exit()
            best_direct.append(g)
    if best_direct:
        # keep the top-N direct matches as 1-hop paths
        best_direct.sort(key=lambda g: (ret_rank_of(g), g.instr_count or 0, g.address))
        for g in best_direct[:limit]:
            results.append([g])
        if len(results) >= limit:
            return results

    # ----------------------------------------------------
    # Phase 2: compose from reg/mem hops depending on kv
    # ----------------------------------------------------
    # A) Source is memory → [memread T] + [arith dst,T]
    if _is_src_mem() and D:
        # Choose T from allowed regs (avoid clobbering D)
        for T in allow:
            if D and T == D:
                continue
            # Hop1: memread T,[src]
            mr_paths = find_memread_chain(dst=T, base=src_base, gadgets=gadgets, args=args)
            if not mr_paths:
                continue
            # Hop2: arith D,T
            for g2 in gadgets:
                if not is_clean_ret(g2):
                    continue
                spec = {"op": op_pat, "dst": D, "src": T}
                if gadget_matches(g2, _arith_match_args(spec)):
                    for p in mr_paths[:1]:
                        path = p + [g2]
                        results.append(path)
                        if len(results) >= limit:
                            return sorted(results, key=_rank_path)

    # B) Dest is memory → memread T,[dst]; (op T,S); memwrite [dst],T
    if _is_dst_mem() and S:
        for T in allow:
            if S and T == S:
                continue
            # Hop1: load memory into T
            mr_paths = find_memread_chain(dst=T, base=dst_base, gadgets=gadgets, args=args)
            if not mr_paths:
                continue
            # Hop2: arith T,S
            arith_cands = []
            for g2 in gadgets:
                if not is_clean_ret(g2):
                    continue
                spec = {"op": op_pat, "dst": T, "src": S}
                if gadget_matches(g2, _arith_match_args(spec)):
                    arith_cands.append(g2)
            if not arith_cands:
                continue
            arith_cands.sort(key=lambda g: (ret_rank_of(g), g.instr_count or 0, g.address))
            g2 = arith_cands[0]
            # Hop3: write back T to memory
            mw_paths = find_memwrite_chain(src=T, base=dst_base, gadgets=gadgets, args=args)
            if not mw_paths:
                continue
            for p1 in mr_paths[:1]:
                for p3 in mw_paths[:1]:
                    path = p1 + [g2] + p3
                    results.append(path)
                    if len(results) >= limit:
                        return sorted(results, key=_rank_path)

    # C) Reg/Reg compose with shims
    if D and S and not (_is_src_mem() or _is_dst_mem()):
        # C1) Pre-shim S->T then (op D,T)
        for T in allow:
            # Skip identity
            if T == S:
                continue
            if T == D:
                continue
            # (op D,T)
            arith_cands = []
            for g2 in gadgets:
                if not is_clean_ret(g2):
                    continue
                spec = {"op": op_pat, "dst": D, "src": T}
                if gadget_matches(g2, _arith_match_args(spec)):
                    arith_cands.append(g2)
            if arith_cands:
                reg_paths = find_reg_chain(src=S, dst=T, gadgets=gadgets, args=args)
                if reg_paths:
                    g2 = sorted(arith_cands, key=lambda g: (ret_rank_of(g), g.instr_count or 0, g.address))[0]
                    for p in reg_paths[:1]:
                        path = p + [g2]
                        results.append(path)
                        if len(results) >= limit:
                            return sorted(results, key=_rank_path)


        # C2b) Pre-shim D->T ; (op T,S) ; T->D
        # Use when an op writing directly to D isn't available but exists for some T.
        for T in allow:
            if T == D or T == S:
                continue

            # Hop1: D -> T
            pre_paths = find_reg_chain(src=D, dst=T, gadgets=gadgets, args=args)
            if not pre_paths:
                continue

            # Hop2: (op T,S)
            arith_cands = []
            for g2 in gadgets:
                if not is_clean_ret(g2):
                    continue
                spec = {"op": op_pat, "dst": T, "src": S}
                if gadget_matches(g2, _arith_match_args(spec)):
                    arith_cands.append(g2)
            if not arith_cands:
                continue
            arith_cands.sort(key=lambda g: (ret_rank_of(g), g.instr_count or 0, g.address))
            g2 = arith_cands[0]

            # we actually do not need to transfer T to D
            # Hop3: T -> D
            post_paths = find_reg_chain(src=T, dst=D, gadgets=gadgets, args=args)
            if not post_paths:
                continue
            
            # Stitch best small paths: keep one pre, one post to avoid explosion
            for p1 in pre_paths[:1]:
                for p3 in post_paths[:1]:
                    path = p1 + [g2]# + p3
                    results.append(path)
                    if len(results) >= limit:
                        return sorted(results, key=_rank_path)

        '''
        # C2) (op T,S) then post-shim T->D
        for T in allow:
            if T == D:
                continue
            arith_cands = []
            for g2 in gadgets:
                if not is_clean_ret(g2):
                    continue
                spec = {"op": op_pat, "dst": T, "src": S}
                if gadget_matches(g2, _arith_match_args(spec)):
                    arith_cands.append(g2)
            if arith_cands:
                reg_paths = find_reg_chain(src=T, dst=D, gadgets=gadgets, args=args)
                if reg_paths:
                    g2 = sorted(arith_cands, key=lambda g: (ret_rank_of(g), g.instr_count or 0, g.address))[0]
                    for p in reg_paths[:1]:
                        path = [g2] + p
                        results.append(path)
                        if len(results) >= limit:
                            return sorted(results, key=_rank_path)

        # C3) Two shims: S->T ; (op U,T) ; U->D
        for T in allow:
            for U in allow:
                if T == S or U == D:
                    continue
                arith_cands = []
                for g2 in gadgets:
                    if not is_clean_ret(g2):
                        continue
                    spec = {"op": op_pat, "dst": U, "src": T}
                    if gadget_matches(g2, _arith_match_args(spec)):
                        arith_cands.append(g2)
                if not arith_cands:
                    continue
                pre = find_reg_chain(src=S, dst=T, gadgets=gadgets, args=args)
                post = find_reg_chain(src=U, dst=D, gadgets=gadgets, args=args)
                if not pre or not post:
                    continue
                g2 = sorted(arith_cands, key=lambda g: (ret_rank_of(g), g.instr_count or 0, g.address))[0]
                for p1 in pre[:1]:
                    for p3 in post[:1]:
                        path = p1 + [g2] + p3
                        results.append(path)
                        if len(results) >= limit:
                            return sorted(results, key=_rank_path)
        '''

    return sorted(results, key=_rank_path)[:limit]


# --- auto-wrap functions for debug trace ---

#_reg2reg_lea_disp_rank = _trace(_reg2reg_lea_disp_rank)
#_hop_args = _trace(_hop_args)
#_copy_chain_args = _trace(_copy_chain_args)
#_reg_protected_set = _trace(_reg_protected_set)
#_clobbers_any = _trace(_clobbers_any)
#_avoid_memref_blocks_intermediate = _trace(_avoid_memref_blocks_intermediate)
#is_clean_ret = _trace(is_clean_ret)
#mem_op_pref = _trace(mem_op_pref)
#build_transfer_edges = _trace(build_transfer_edges)
find_reg_chain = _trace(find_reg_chain)
find_memread_chain = _trace(find_memread_chain)
find_memwrite_chain = _trace(find_memwrite_chain)
find_arith_chain = _trace(find_arith_chain)

# --- end auto-wrap ---
