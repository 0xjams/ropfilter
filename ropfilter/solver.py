# ropfilter/solver.py (NO-OPT + human-logs) — v0.2.20-noopt-log
from __future__ import annotations
from typing import Dict, List, Any, Optional, Tuple
import json
import os

# Logging (kept as-is; no caching/optimizations used)
try:
    from .debuglog import DebugLog, _NullLogger
except Exception:
    from debuglog import DebugLog, _NullLogger

_DBG = _NullLogger()

from .constants import REGS
from .filters import gadget_matches
from .ranking import ret_rank_of, memread_disp_rank, memwrite_disp_rank
from .output import gadget_to_text
from . import chain as chainmod  # imported but chain fallbacks are not used in NO-OPT path
from .utils import set_exact_reg_mode, now, elapsed_since, get_disp_key

try:
    import yaml  # Optional; if unavailable, YAML specs are not supported.
    _HAS_YAML = True
except Exception:
    _HAS_YAML = False


# --- v0.2.20-noopt-log: human-friendly debug helpers -----------------

def _gline(g, base_addr=None):
    """Safe gadget one-liner for logs."""
    try:
        if isinstance(g,str):
            return gadget_to_text(g, base_addr)
        elif isinstance(g,list):
            return "->".join([gadget_to_text(i, base_addr) for i in g])
        else:
            return gadget_to_text(g, base_addr)
    except Exception:
        addr = getattr(g, "address", None)
        ic   = getattr(g, "instr_count", None)
        return f"<gadget addr={hex(addr) if isinstance(addr,int) else addr} ic={ic}>"

def _fmt_kv(kv):
    """Render small dicts like: dst=eax, base=esi, disp<=64, op=mov"""
    if not isinstance(kv, dict):
        return repr(kv)
    parts = []
    for k in sorted(kv.keys()):
        v = kv[k]
        parts.append(f"{k}={v}")
    return ", ".join(parts)

def _fmt_node(node):
    """Pretty print a constraint node (top-level)."""
    if not isinstance(node, dict):
        return repr(node)
    # single-key leaf like {"memread": {...}}
    if len(node) == 1:
        k, v = next(iter(node.items()))
        if isinstance(v, dict):
            return f"{k}({ _fmt_kv(v) })"
        if isinstance(v, list):
            return f"{k}[{len(v)}]"
        return f"{k}={v}"
    # composite (any_of/all_of/not/etc.)
    keys = ", ".join(sorted(node.keys()))
    return f"node[{keys}]"

def _log(msg, **kw):
    """Human-readable + structured."""
    # Human text goes into 'text'; structured fields remain accessible.
    try:
        _DBG.emit("log", text=str(msg), **kw)
    except Exception:
        # Never interrupt the solver on logging errors
        pass


# ---------------------------
# Spec loading (JSON / YAML)
# ---------------------------

def load_solve_spec(spec_json: Optional[str], spec_file: Optional[str]) -> Dict[str, Any]:
    if spec_json:
        try:
            data = json.loads(spec_json)
            _log("Loaded solve spec from --solve-json",
                 source="json",
                 size=len(spec_json),
                 top_keys=list(data.keys()) if isinstance(data, dict) else None)
            return data
        except Exception as e:
            _log("Failed parsing --solve-json", error=str(e))
            raise SystemExit(f"--solve-json parse error: {e}")
    if spec_file:
        if not os.path.exists(spec_file):
            _log("Solve spec file not found", path=spec_file)
            raise SystemExit(f"--solve-file not found: {spec_file}")
        data = open(spec_file, "r", encoding="utf-8").read()
        # Decide by extension first; fallback probing
        if spec_file.lower().endswith((".yml", ".yaml")):
            if not _HAS_YAML:
                _log("YAML unavailable while .yml requested")
                raise SystemExit("PyYAML not installed; please `pip install pyyaml`, or use JSON via --solve-json/--solve-file.")
            try:
                doc = yaml.safe_load(data) or {}
                _log("Loaded solve spec from YAML file",
                     source="yaml",
                     path=spec_file,
                     top_keys=list(doc.keys()) if isinstance(doc, dict) else None)
                return doc
            except Exception as e:
                _log("YAML parse error", path=spec_file, error=str(e))
                raise SystemExit(f"--solve-file YAML parse error: {e}")
        # JSON (or try JSON first)
        try:
            doc = json.loads(data)
            _log("Loaded solve spec from JSON file",
                 source="json",
                 path=spec_file,
                 top_keys=list(doc.keys()) if isinstance(doc, dict) else None)
            return doc
        except Exception:
            # fallback: if YAML available, try
            if _HAS_YAML:
                try:
                    doc = yaml.safe_load(data) or {}
                    _log("Loaded solve spec by fallback YAML",
                         source="yaml-fallback",
                         path=spec_file,
                         top_keys=list(doc.keys()) if isinstance(doc, dict) else None)
                    return doc
                except Exception as e:
                    _log("Solve spec parse failed for both JSON and YAML",
                         path=spec_file, error=str(e))
                    raise SystemExit(f"--solve-file parse error (JSON+YAML both failed): {e}")
            _log("Solve spec parse failed (JSON only)", path=spec_file)
            raise SystemExit("--solve-file parse error: not valid JSON; YAML support not available.")
    _log("Neither --solve-json nor --solve-file provided")
    raise SystemExit("Provide either --solve-json or --solve-file.")


# ---------------------------
# Constraint machinery (NO-OPT)
# ---------------------------

class Binding:
    """Variable → register mapping."""
    def __init__(self, mapping: Optional[Dict[str, str]] = None):
        self.map: Dict[str, str] = dict(mapping or {})

    def get(self, var: str) -> Optional[str]:
        return self.map.get(var)

    def set(self, var: str, reg: str) -> "Binding":
        m = dict(self.map)
        m[var] = reg
        return Binding(m)

    def __repr__(self) -> str:
        return f"Binding({self.map})"


def _vars_from_spec(spec: Dict[str, Any]) -> List[str]:
    vs = spec.get("vars") or []
    if not isinstance(vs, list) or not all(isinstance(v, str) for v in vs):
        raise SystemExit("Solve spec must contain 'vars' as a list of variable names.")
    return [v.strip() for v in vs]


def _constraints(spec: Dict[str, Any]) -> List[Dict[str, Any]]:
    cs = spec.get("constraints") or []
    if not isinstance(cs, list):
        raise SystemExit("'constraints' must be a list.")
    return cs


def _domains_from_spec(vars_list: List[str], spec: Dict[str, Any]) -> Dict[str, List[str]]:
    """NO-OPT: only honor 'in' and 'notin' at load time. No propagation/seed logic."""
    dom: Dict[str, List[str]] = {v: list(REGS) for v in vars_list}

    for c in spec.get("constraints", []):
        if "in" in c:
            v = c["in"].get("var")
            s = [r.strip().lower() for r in c["in"].get("set", [])]
            if v in dom:
                before = list(dom[v])
                dom[v] = [r for r in dom[v] if r in s]
                _log(f"Domain narrowed by 'in' for {v}: {before} -> {dom[v]}")
        if "notin" in c:
            v = c["notin"].get("var")
            s = {r.strip().lower() for r in c["notin"].get("set", [])}
            if v in dom:
                before = list(dom[v])
                dom[v] = [r for r in dom[v] if r not in s]
                _log(f"Domain narrowed by 'notin' for {v}: {before} -> {dom[v]}")
    return dom


def _neq_pairs(spec: Dict[str, Any]) -> List[Tuple[str, str]]:
    """NO-OPT: gather pairwise neq/distinct; enforced during search."""
    def _pairs(lst):
        for i in range(len(lst)):
            for j in range(i + 1, len(lst)):
                yield (lst[i], lst[j])

    out: List[Tuple[str, str]] = []
    for c in spec.get("constraints", []) or []:
        for key in ("neq", "distinct"):
            if key in c:
                val = c[key]
                if isinstance(val, list) and len(val) >= 2:
                    out.extend(_pairs(val))
    if out:
        _log("Collected neq/distinct pairs", pairs=out)
    return out


def _eq_pairs(spec: Dict[str, Any]) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for c in spec.get("constraints", []) or []:
        if "same" in c and isinstance(c["same"], list) and len(c["same"]) == 2:
            a, b = c["same"][0], c["same"][1]
            out.append((a, b))
    if out:
        _log("Collected equality pairs", pairs=out)
    return out


def _violates_neq(bind: Binding, neq_pairs: List[Tuple[str, str]]) -> bool:
    for a, b in neq_pairs:
        va, vb = bind.get(a), bind.get(b)
        if va is not None and vb is not None and va == vb:
            _log(f"Prune by neq: {a}={va} must != {b}={vb}", binding=dict(bind.map))
            return True
    return False


def _violates_eq(bind: Binding, eq_pairs: List[Tuple[str, str]]) -> bool:
    for a, b in eq_pairs:
        va, vb = bind.get(a), bind.get(b)
        if va is not None and vb is not None and va != vb:
            _log(f"Prune by eq: {a}={va} must == {b}={vb}", binding=dict(bind.map))
            return True
    return False

# solver.py — add after _apply_binding_to_kv()
def _apply_binding_to_kv_keys(kv: Dict[str, Any], bind: Binding, keys: List[str]) -> Dict[str, Any]:
    """Apply binding only to selected keys (e.g., reg/dst/src/base)."""

    if not isinstance(kv, dict):
        return kv
    out = dict(kv)
    for k in keys:
        if k in out and isinstance(out[k], str):
            out[k] = bind.map.get(out[k], out[k])
    _log("Applied binding to selected keys", keys=keys, kv_in=kv, kv_out=out, binding=dict(bind.map))
    return out


def _apply_binding_to_kv(kv: Dict[str, Any], bind: Binding) -> Dict[str, Any]:
    """Replace variable tokens in kv according to current binding (NO-OPT)."""
    def _resolve(val):
        if isinstance(val, str):
            return bind.map.get(val, val)
        if isinstance(val, (list, tuple)):
            return [ _resolve(x) for x in val ]
        if isinstance(val, dict):
            return { k: _resolve(v) for k, v in val.items() }
        return val
    if isinstance(kv, str):
        return bind.map.get(kv, kv)

    out = { k: _resolve(v) for k, v in kv.items() }
    _log("Applied binding to predicate", kv_in=kv, kv_out=out, binding=dict(bind.map))
    return out


def _mk_temp_args(args):
    """Minimal temp args, no memoization/caching."""
    class T: pass
    temp = T()
    for k, v in vars(args).items():
        setattr(temp, k, v)
    if not hasattr(temp, "reg2reg_specs"):  temp.reg2reg_specs = []
    if not hasattr(temp, "memread_specs"):  temp.memread_specs = []
    if not hasattr(temp, "memwrite_specs"): temp.memwrite_specs = []
    if not hasattr(temp, "arith_specs"):    temp.arith_specs = []
    return temp


def _normalize_spec_kv_for_filters(kv: Dict[str, Any]) -> Dict[str, Any]:
    """Light normalization; keep behavior compatible with filters.gadget_matches."""
    if isinstance(kv, str):
        _log("Normalized skipped on str", before=kv, after=kv)
        return kv
    out: Dict[str, Any] = {}

    if isinstance(kv, str):
        try:
            kv = parse_kvlist(kv) or {}
        except Exception:
            kv = {}
    elif kv is None:
        kv = {}
    elif not isinstance(kv, dict):
        try:
            kv = dict(kv)  # best effort for Mapping-like objects
        except Exception:
            kv = {}

    def _fix_key(k: str) -> str:
        k = k.strip()
        if k.endswith(":"):
            k = k[:-1]
        if k.endswith("=") and ("<" not in k and ">" not in k):
            k = k[:-1]
        return k

    for k, v in kv.items():
        k2 = _fix_key(k)
        if k2 in ("abs", "dst_abs", "src_abs") and isinstance(v, int):
            out[k2] = hex(v)
        else:
            out[k2] = v
    if out != kv:
        _log("Normalized predicate KV", before=kv, after=out)
    return out


def _rank_key_for(g, temp_args):
    """Ranking kept for stable output; not an optimization path."""
    if getattr(temp_args, "memwrite_specs", None):
        disp_rank, is_abs = memwrite_disp_rank(g, temp_args.memwrite_specs)
    elif getattr(temp_args, "memread_specs", None):
        disp_rank, is_abs = memread_disp_rank(g, temp_args.memread_specs)
    else:
        disp_rank, is_abs = (0, 0)

    rrank  = ret_rank_of(g)
    length = getattr(g, "instr_count", 0) or 0
    addr   = getattr(g, "address", 0)
    return (disp_rank, rrank, length, is_abs, addr)


def _predicate_witness(kind: str, kv: Dict[str, Any], gadgets, args) -> Optional[Any]:
    """Chain-aware witness finder. Always searches chains using chain.py helpers."""
    _log(f"[predicate] enter {kind}", kv=kv)
    temp = _mk_temp_args(args)
    ty = type(kv)
    kv = _normalize_spec_kv_for_filters(kv)
    # Map common 'clobber' → avoid_clobber for memread/memwrite/arith/reg2reg
    def _apply_clobber(_temp, _kv):
        cl = _kv.pop("clobber", None)
        if cl is not None:
            _temp.avoid_clobber = [cl] if isinstance(cl, str) else list(cl)
            _log("[predicate] apply clobber→avoid_clobber", avoid=_temp.avoid_clobber)

    # Clear specs
    temp.reg2reg_specs = []
    temp.memread_specs = []
    temp.memwrite_specs = []
    temp.arith_specs = []
    temp.arith = []
    temp.pop_seq = []
    '''
    dead code
    # Dispatch predicates that aren't chainable stay direct
    if kind == "dispatch":
        want_kind = (kv.get("kind") or "any").lower()
        want_mode = (kv.get("mode") or "any").lower()
        want_reg  = kv.get("reg")
        want_abs  = kv.get("abs")
        if isinstance(want_abs, str):
            try: want_abs = int(want_abs, 0)
            except: want_abs = None

        best = None
        best_key = None
        scanned = 0
        matched = 0
        for g in gadgets:
            scanned += 1
            if not gadget_matches(g, temp):
                continue
            for d in getattr(g, "dispatch", []):
                if want_kind != "any" and d.kind != want_kind:
                    continue
                ok = False
                if want_mode == "reg" and d.target == "reg":
                    ok = (want_reg is None) or (d.reg == want_reg)
                elif want_mode == "abs" and d.target == "abs":
                    ok = (want_abs is None) or (d.absolute == want_abs)
                elif want_mode == "mem" and d.target == "mem":
                    ok = True
                else:
                    ok = True  # 'any'
                if ok:
                    matched += 1
                    k = _rank_key_for(g, temp)
                    if best is None or k < best_key:
                        best, best_key = g, k
                    break
        _log(f"[predicate] exit {kind}", scanned=scanned, matched=matched, best=_gline(best) if best else None)
        return [best] if best is not None else None

    if kind == "pivot":
        temp.pivot = True
        if kv.get("kind"): temp.pivot_kind = kv["kind"]
        if kv.get("reg"): temp.pivot_reg = kv["reg"]
        if kv.get("imm") is not None:
            try: temp.pivot_imm = int(kv["imm"], 0) if isinstance(kv["imm"], str) else int(kv["imm"])
            except: pass

        best = None
        best_key = None
        scanned = 0
        matched = 0
        for g in gadgets:
            scanned += 1
            if gadget_matches(g, temp):
                matched += 1
                k = _rank_key_for(g, temp)
                if best is None or k < best_key:
                    best, best_key = g, k
        _log(f"[predicate] exit {kind}", scanned=scanned, matched=matched, best=_gline(best) if best else None)
        return [best] if best is not None else None
    '''
    # Chainable kinds
    if kind == "reg2reg":
        _apply_clobber(temp, kv)
        src = kv.get("src"); dst = kv.get("dst")
        if src is None or dst is None:
            _log("[predicate] reg2reg missing src/dst → fail", kv=kv)
            return None
        chains = chainmod.find_reg_chain(src, dst, gadgets, temp)
        if chains:
            _log("[predicate] reg2reg via chain", picked=len(chains[0]), path=[_gline(g) for g in chains[0]])
            return chains[:1]
        _log("[predicate] reg2reg no chain found", kv=kv)
        return None

    if kind == "memread":
        _apply_clobber(temp, kv)
        disp_key =  get_disp_key(kv)
        disp_value = kv[disp_key]
        op   = kv.get("op")
        temp.memread_specs.append({"op":op, disp_key: disp_value})
        dst = kv.get("dst"); base = kv.get("base")
        if dst is None or base is None:
            _log("[predicate] memread missing dst/base → fail", kv=kv)
            return None
        chains = chainmod.find_memread_chain(dst, base, gadgets, temp)
        if chains:
            _log("[predicate] memread via chain", picked=len(chains[0]), path=[_gline(g) for g in chains[0]])
            return chains[:1]
        _log("[predicate] memread no chain found", kv=kv)
        return None

    if kind == "memwrite":
        _apply_clobber(temp, kv)
        disp_key =  get_disp_key(kv)
        disp_value = kv[disp_key]
        op   = kv.get("op")
        temp.memwrite_specs.append({"op":op, disp_key: disp_value})
        src = kv.get("src"); base = kv.get("base")
        if src is None or base is None:
            _log("[predicate] memwrite missing src/base → fail", kv=kv)
            return None
        chains = chainmod.find_memwrite_chain(src, base, gadgets, temp)
        if chains:
            _log("[predicate] memwrite via chain", picked=len(chains[0]), path=[_gline(g) for g in chains[0]])
            return chains[:1]
        _log("[predicate] memwrite no chain found", kv=kv)
        return None

    if kind == "arith":
        _apply_clobber(temp, kv)
        chains = chainmod.find_arith_chain(kv, gadgets, temp)
        if chains:
            _log("[predicate] arith via chain", picked=len(chains[0]), path=[_gline(g) for g in chains[0]])
            return chains[:1]
        _log("[predicate] arith no chain found", kv=kv)
        return None

    if kind == "pop":
        # pop: { dst|reg: <reg/var>, count?: int, position?: "first"|"last"|"any" (default any) }
        _apply_clobber(temp, kv)
        dst = kv.get("dst", kv.get("reg"))
        temp.pop_seq = [dst]
        if not dst:
            _log("[predicate] pop missing dst/reg → fail", kv=kv)
            return None
        try:
            want_count = int(kv["count"]) if "count" in kv and kv["count"] is not None else None
        except Exception:
            want_count = None
        pos = (kv.get("position") or "any").lower()

        best = None
        best_key = None
        scanned = 0
        matched = 0
        for g in gadgets:
            scanned += 1
            if not gadget_matches(g, temp):
                continue
            pops = getattr(g, "pops", []) or []
            c = pops.count(dst)
            if c == 0:
                continue
            if want_count is not None and c != want_count:
                continue
            if pos == "first" and (not pops or pops[0] != dst):
                continue
            if pos == "last" and (not pops or pops[-1] != dst):
                continue
            matched += 1
            k = _rank_key_for(g, temp)
            if best is None or k < best_key:
                best, best_key = g, k

        _log(f"[predicate] exit {kind}", scanned=scanned, matched=matched, best=_gline([best]) if best else None)
        #exit()
        return [best] if best is not None else None


    # Fallback: unknown kind -> no witness
    _log("[predicate] unknown kind", kind=kind, kv=kv)
    return None



def _apply_global_spec_overrides(args, spec):
    """Overlay global knobs from the spec into args (NO-OPT)."""
    '''
    options:
      exact_reg: true          # eax ≠ ax ≠ al
      stable_dst: true         # enable smart overwrite protection during solving on dst
      stable_src: true         # enable smart overwrite protection during solving on src
      avoid_memref: "*"        # reject gadgets with memref to other registers than base in memread|memwrite filters
      
    limits:
      max_instr: 5            # max instructions per gadget keep it similar to rop++ -r 
      max_solutions: 2        # max solutions to solve
      retn: 0x20               # accept only gadgets with ret or retn N < 0x20

    memory:
      strict: true             # reject absolute [0x...]
      protect_stack: true

  '''

    # Apply options
    spec_options = spec.get("options", {}) or {}
    _log("Spec options received", options=spec_options)

    if bool(spec_options.get("exact_reg", False)):
        setattr(args, "exact_reg", True)
        set_exact_reg_mode(True)
        _log("Enabled exact register matching")
    if "stable_dst" in spec_options:
        setattr(args, "stable_dst", bool(spec_options["stable_dst"]))
        _log("Set stable_dst", value=bool(spec_options["stable_dst"]))
    if "stable_src" in spec_options:
        setattr(args, "stable_src", bool(spec_options["stable_src"]))
        _log("Set stable_src", value=bool(spec_options["stable_src"]))
    if "avoid_memref" in spec_options and spec_options["avoid_memref"] is not None:
        setattr(args, "avoid_memref", str(spec_options["avoid_memref"]))
        _log("Set avoid_memref", value=str(spec_options["avoid_memref"]))

    limits = (spec.get("limits") or {})

    _log("Spec limits received", limits=limits)

    if "max_instr" in limits:          setattr(args, "max_instr", int(limits["max_instr"]))
    if "ret_only" in limits:           setattr(args, "ret_only", bool(limits["ret_only"]))
    if "retn" in limits and limits["retn"] is not None:
        setattr(args, "retn", limits["retn"])
    if "max_stack_delta" in limits:    setattr(args, "max_stack_delta", int(limits["max_stack_delta"]))

    if "bad_bytes" in limits:
        bad = limits.get("bad_bytes")
        if len(bad) > 0:
            bb = []
            for tok in bad:
                #t = str(tok).lower().strip()
                #if t.startswith("0x"): t = t[2:]
                #print(tok)
                #bb.append(int(t, 16))
                bb.append(tok)
                #print(bb)

            setattr(args, "addr_no_bytes", bb)
            #exit()

    mem = (spec.get("memory") or {})
    _log("Spec memory received", memory=mem)
    if "strict" in mem:
        setattr(args, "strict_mem", bool(mem["strict"]))

    if "protect_stack" in mem:
        setattr(args, "protect_stack", bool(mem["protect_stack"]))
        _log("Set protect_stack", value=bool(mem["protect_stack"]))


def _satisfied_and_witness(bind: Binding, constraints: List[Dict[str, Any]], gadgets, args) -> Tuple[bool, Dict[str, Any]]:
    """Evaluate constraints; collect witnesses. NO-OPT: no caching or branch re-ordering."""
    witnesses: Dict[str, Any] = {}

    def _eval_one(idx: int, node: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        _log("Evaluate node", index=idx, node=_fmt_node(node), binding=dict(bind.map))

        # NOT
        if "not" in node:
            ok, _w = _eval_one(idx, node["not"])
            _log("NOT node result", index=idx, ok=ok)
            return (not ok), {}

        # ANY_OF (simple order; no heuristics)
        if "any_of" in node:
            for j, sub in enumerate(node["any_of"], 1):
                _log("ANY_OF branch try", any_of_index=idx, branch=j, node=_fmt_node(sub))
                ok, w = _eval_one(idx, sub)
                if ok:
                    _log("ANY_OF branch satisfied", any_of_index=idx, branch=j)
                    return True, {f"any_of[{idx}]/choice{j}": w if w else "ok"}
            _log("ANY_OF failed", any_of_index=idx)
            return False, {}

        # ALL_OF
        if "all_of" in node:
            combined = {}
            for j, sub in enumerate(node["all_of"], 1):
                _log("ALL_OF part try", all_of_index=idx, part=j, node=_fmt_node(sub))
                ok, w = _eval_one(idx, sub)
                if not ok:
                    _log("ALL_OF failed part", all_of_index=idx, part=j)
                    return False, {}
                combined.update(w)
            _log("ALL_OF satisfied", all_of_index=idx, parts=len(node["all_of"]))
            return True, combined

        # Domain-only nodes: no-op here
        for domkey in ("in", "notin", "neq", "distinct"):
            if domkey in node:
                _log("Domain-only node ignored at eval", index=idx, node=_fmt_node(node))
                return True, {}

        # Leaf predicates
        for kind in ("reg2reg", "memwrite", "memread", "arith", "dispatch", "pivot", "pop_seq", "pop"):
            if kind in node:                
                kv = node[kind]
                if kind in ("reg2reg", "memwrite", "memread", "arith", "pop", "pop_seq"):
                    # full variable substitution (IDs, base/dst/src/disp constraints, etc.)
                    kv = _apply_binding_to_kv(kv, bind)
                elif kind in ("dispatch", "pivot"):
                    # conservative: only substitute fields that are registers if they refer to variables
                    kv = _apply_binding_to_kv_keys(kv, bind, keys=["reg", "dst", "src", "base"])

                _log("Leaf predicate evaluate", index=idx, kind=kind, kv=_fmt_kv(kv))
                g = _predicate_witness(kind, kv, gadgets, args)

                if g is None:
                    _log("Leaf predicate failed", index=idx, kind=kind)
                    return False, {}
                _log("Leaf predicate satisfied", index=idx, kind=kind, gadget=[_gline(g_1) for g_1 in g])
                #exit()
                return True, {f"{kind}[{idx}]": g}

        # Unknown node
        _log("Unknown/unsupported node", index=idx, node=str(node))
        return False, {}

    for idx, c in enumerate(constraints):
        ok, w = _eval_one(idx, c)
        if not ok:
            _log("Constraint failed", index=idx, node=_fmt_node(c))
            return False, {}
        witnesses.update(w)

    _log("All constraints satisfied under binding", binding=dict(bind.map))
    return True, witnesses


def solve(spec: Dict[str, Any], gadgets, args) -> List[Dict[str, Any]]:
    t0 = now()
    global _DBG
    if getattr(args, "debug_file", None):
        _DBG = DebugLog(args.debug_file)
        _DBG.emit("solve_start",
                  constraints=len(spec.get("constraints") or []),
                  gadgets=len(gadgets or []),
                  args={k: getattr(args, k) for k in dir(args) if not k.startswith("_")})
    else:
        _DBG = _NullLogger()

    vars_list   = _vars_from_spec(spec)
    constraints = _constraints(spec)

    _apply_global_spec_overrides(args, spec)
    _log("Applied global limits/memory/address",
         limits=spec.get("limits"),
         address=spec.get("address"),
         memory=spec.get("memory"))

    domains   = _domains_from_spec(vars_list, spec)
    _log("Initial domains", domains=domains)

    neq_pairs = _neq_pairs(spec)
    eq_pairs  = _eq_pairs(spec)

    # NO OPTIMIZATIONS: no gadget prefilter; no domain propagation; no ESP seeding.
    # Variable order: keep the order given in spec (left-to-right).
    order = list(vars_list)
    _log("Variable search order", order=order)

    limits = (spec.get("limits") or {})
    max_solutions = int(limits.get("max_solutions", getattr(args, "solve_max_solutions", 10)))
    _log("Max solutions", max_solutions=max_solutions)

    solutions: List[Dict[str, Any]] = []
    nodes = 0

    def backtrack(i: int, bind: Binding):
        nonlocal nodes
        nodes += 1
        if len(solutions) >= max_solutions:
            _log("Stop: reached max_solutions", count=len(solutions))
            return
        # Early pruning on eq/neq
        if _violates_neq(bind, neq_pairs):
            return
        if _violates_eq(bind, eq_pairs):
            return

        if i >= len(order):
            _log("Try full binding", binding=dict(bind.map))
            ok, wit = _satisfied_and_witness(bind, constraints, gadgets, args)
            if ok:
                _log("Solution accepted", binding=dict(bind.map))
                solutions.append({"binding": bind.map, "witness": wit, "constraints": constraints})
            else:
                _log("Full binding rejected", binding=dict(bind.map))
            return

        v = order[i]
        regs = domains.get(v, REGS)
        _log("Choose variable", var=v, domain=regs)
        for reg in regs:
            _log("Bind try", var=v, reg=reg, depth=i)
            b2 = bind.set(v, reg)
            backtrack(i + 1, b2)

    backtrack(0, Binding())
    took = elapsed_since(t0)
    _log("Solve finished", nodes=nodes, solutions=len(solutions), took=took)
    print("took", took)   # e.g., "took 1 hour, 4 mins, 3 sec"
    _DBG.emit("solve_end", solutions=len(solutions or []))
    _DBG.close()
    return solutions



def print_solutions(solutions: List[Dict[str, Any]], args, base_addr=None):
    def _pp_witness(key: str, obj: Any, indent: int = 2):
        pad = " " * indent

        # Try pretty-gadget first
        try:
            line = gadget_to_text(obj, base_addr)
            print(f"{pad}{key}: {line}")
            return
        except Exception:
            pass

        # Multiple paths (kept, though chains aren't used in this NO-OPT build)
        if isinstance(obj, list) and obj and isinstance(obj[0], list):
            print(f"{pad}{key}:")
            for pidx, path in enumerate(obj, 1):
                print(f"{pad}  Path {pidx}:")
                for g in path:
                    try:
                        print(f"{pad}    - {gadget_to_text(g, base_addr)}")
                    except Exception:
                        print(f"{pad}    - {repr(g)}")
            return

        # Single path: list of gadgets
        if isinstance(obj, list):
            print(f"{pad}{key}:")
            for g in obj:
                try:
                    print(f"{pad}  - {gadget_to_text(g, base_addr)}")
                except Exception:
                    print(f"{pad}  - {repr(g)}")
            return

        # Nested dict (e.g., any_of/all_of sub-witness)
        if isinstance(obj, dict):
            print(f"{pad}{key}:")
            for subk, subv in obj.items():
                _pp_witness(str(subk), subv, indent + 2)
            return

        # Fallback scalar/unknown
        print(f"{pad}{key}: {repr(obj)}")

    if not solutions:
        print("(no solutions)")
        return

    for idx, sol in enumerate(solutions, 1):
        print(f"=== Solution {idx} ===")
        bind = sol.get("binding", {})
        print("Bindings:")
        for k in sorted(bind):
            print(f"  {k} = {bind[k]}")

        print("Witnesses:")
        wit = sol.get("witness", {})
        if not wit:
            print("  (none)")
        else:
            for key in sorted(wit.keys()):
                _pp_witness(str(key), wit[key], indent=2)
        print()
        print("--------------------------------------------------------")