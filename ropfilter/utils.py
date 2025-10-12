# ropfilter/utils.py
from __future__ import annotations
import re
from typing import Optional, Dict, Set
from .constants import REGSET
import json

# Extra register families (not normalized by norm_reg)
# Extra register families recognized but not normalized to GPRs
_EXTRA_VEC_FP = {
    # x87 stack regs
    "st": "st0", "st0":"st0","st1":"st1","st2":"st2","st3":"st3","st4":"st4","st5":"st5","st6":"st6","st7":"st7",
    # MMX
    "mm0":"mm0","mm1":"mm1","mm2":"mm2","mm3":"mm3","mm4":"mm4","mm5":"mm5","mm6":"mm6","mm7":"mm7",
    # SSE (x86 era 0..7)
    "xmm0":"xmm0","xmm1":"xmm1","xmm2":"xmm2","xmm3":"xmm3",
    "xmm4":"xmm4","xmm5":"xmm5","xmm6":"xmm6","xmm7":"xmm7",
}


# SIB displacement sentinels (used when [base ± idx*scale] has NO trailing immediate)
SIB_DISP_POS = 0x40000000   # +1,073,741,824
SIB_DISP_NEG = -0x40000000  # -1,073,741,824

# --- global matching mode switches ---
EXACT_REG_MATCH = False

def set_exact_reg_mode(enabled: bool) -> None:
    """If True, do not alias subregisters (eax!=ax!=al)."""
    global EXACT_REG_MATCH
    EXACT_REG_MATCH = bool(enabled)
'''
def canon_reg(x: Optional[str]) -> Optional[str]:
    """
    Canonicalize a register:
      - EXACT_REG_MATCH=True  -> only accept known registers (GPRs, subregs, FPU/MMX/SSE)
      - EXACT_REG_MATCH=False -> alias subregisters to 32-bit via norm_reg, or accept FPU/MMX/SSE as-is
    """
    if x is None:
        return None
    t = x.strip().lower()
    if not t:
        return None

    if EXACT_REG_MATCH:
        # Build once per process (cheap) — acceptable tokens in exact mode
        # NOTE: SUBREG_MAP lives in norm_reg; we replicate the keys here so we don't import cycles
        _subreg_keys = {
            "al","ah","ax","bl","bh","bx","cl","ch","cx","dl","dh","dx",
            "si","sil","di","dil","bp","bpl","sp","spl",
        }
        _ACCEPTABLE_EXACT: Set[str] = set(REGSET) | _subreg_keys | set(_EXTRA_VEC_FP.keys())
        return t if t in _ACCEPTABLE_EXACT else None

    # legacy mode: first try to normalize to 32-bit GPR parent
    r = norm_reg(t)
    if r:
        return r
    # then accept FPU/MMX/SSE families as themselves (no normalization)
    return _EXTRA_VEC_FP.get(t)
'''

# v0.2.24: read helper for debug paths
def get_exact_reg_mode() -> bool:
    return bool(EXACT_REG_MATCH)

def pretty_print_object(obj):
    if isinstance(obj, dict):
        print(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False))
    else:
        print(json.dumps(obj.__dict__, indent=2, sort_keys=True, ensure_ascii=False))

def canon_reg(x: Optional[str]) -> Optional[str]:
    """
    Canonicalize a register token.
    - If EXACT_REG_MATCH is True: only accept known register names (GPRs, common subregs, FPU/MMX/SSE).
    - Else: map subregs to their 32-bit GPR via norm_reg(), or accept FPU/MMX/SSE as-is.
    """
    #print(f"canon_reg: {x} - {EXACT_REG_MATCH}")
    if x is None:
        return None
    t = x.strip().lower()
    if not t:
        return None

    if EXACT_REG_MATCH:
        # Only allow known names in exact mode.
        # Known GPRs
        gprs = {"eax","ebx","ecx","edx","esi","edi","ebp","esp"}
        # Common subregisters we accept verbatim in exact mode
        sub = {"al","ah","ax","bl","bh","bx","cl","ch","cx","dl","dh","dx","si","sil","di","dil","bp","bpl","sp","spl"}
        allowed = gprs | sub | set(_EXTRA_VEC_FP.keys())
        return t if t in allowed else None

    # Legacy mode: prefer normalized GPR, else vector/FPU families
    parent = norm_reg(t)  # maps al->eax, ah->eax, ax->eax, etc.
    if parent:
        return parent
    return _EXTRA_VEC_FP.get(t)

    
# ---- simple text helpers ----
def clean(s: str) -> str:
    return s.strip().lower()

def norm_reg(x: Optional[str]) -> Optional[str]:
    if not x:
        return None
    x = x.strip().lower()

    # direct 32-bit regs
    if x in REGSET:
        return x

    # normalize 8-bit/16-bit subregisters to parent 32-bit
    SUBREG_MAP = {
        "al":"eax", "ah":"eax", "ax":"eax",
        "bl":"ebx", "bh":"ebx", "bx":"ebx",
        "cl":"ecx", "ch":"ecx", "cx":"ecx",
        "dl":"edx", "dh":"edx", "dx":"edx",
        "si":"esi", "sil":"esi",
        "di":"edi", "dil":"edi",
        "bp":"ebp", "bpl":"ebp",
        "sp":"esp", "spl":"esp",
    }
    return SUBREG_MAP.get(x)


def is_reg(tok: str) -> bool:
    return norm_reg(tok) is not None

# ---- numbers / imm ----
IMM_RE = re.compile(r"^(0x[0-9a-fA-F]+|\d+)$")
def parse_imm(tok: str) -> Optional[int]:
    tok = tok.strip().lower()
    if tok.startswith("0x"):
        try: return int(tok,16)
        except: return None
    return int(tok) if tok.isdigit() else None

# ---- memory operand ----
def parse_mem_operand(op: str):
    """
    Accept: [eax], [ecx+0x20], [ecx-4], [0x5054a220],
            [edi+esi*4+0xC4], [edi-esi*4-0x20], [ebx+ecx*2], [ebx-ecx*8]
    Returns: (base_reg, disp, absolute_addr)
    NOTE:
      - If SIB form has NO trailing immediate, disp is set to a large sentinel:
          +idx*scale  -> +SIB_DISP_POS
          -idx*scale  -> -SIB_DISP_NEG
        This prevents accidental matches against small disp filters (e.g., 4, 8, 16).
    """
    s = op.strip()
    if not (s.startswith("[") and s.endswith("]")):
        return (None, None, None)

    inner_raw = s[1:-1]
    inner = inner_raw.strip().replace(" ", "").lower()

    # Absolute: [0x...]
    if inner.startswith("0x") and IMM_RE.match(inner):
        return (None, 0, int(inner, 16))

    # Find base
    base_regs = ("eax","ebx","ecx","edx","esi","edi","ebp","esp")
    base, rest = None, ""
    for r in base_regs:
        if inner.startswith(r):
            base, rest = r, inner[len(r):]
            break

    if base is None:
        return (None, None, None)

    if not rest:
        # [base]
        return (base, 0, None)

    # Simple [base +/- imm]
    if rest[0] in "+-":
        sign1 = 1 if rest[0] == "+" else -1
        imm_s = rest[1:]
        # Pure immediate (no SIB tail)
        if IMM_RE.match(imm_s):
            disp = parse_imm(imm_s)
            if disp is not None:
                return (base, sign1 * disp, None)

    # --- NEW: SIB with optional trailing imm: [base +/- idx*scale [ +/- imm ]]
    # Capture: leading sign, index reg, optional *scale, then tail
    m_sib = re.match(r"([+-])([a-z]{2,3})(?:\*(1|2|4|8))?(.*)$", rest)
    if m_sib:
        sib_lead_sign = m_sib.group(1)     # '+' or '-'
        # idx_reg = m_sib.group(2)         # (not needed for now)
        # idx_scale = m_sib.group(3)       # (not needed for now)
        tail = m_sib.group(4) or ""

        # Trailing immediate (signed, anchored to end)
        m_imm = re.search(r"([+-])(0x[0-9a-f]+|\d+)$", tail)
        if m_imm:
            sgn = 1 if m_imm.group(1) == "+" else -1
            disp = parse_imm(m_imm.group(2))
            if disp is not None:
                return (base, sgn * disp, None)

        # No trailing imm -> use sentinels based on the SIB lead sign
        if sib_lead_sign == "+":
            return (base, SIB_DISP_POS, None)
        else:
            return (base, SIB_DISP_NEG, None)

    # Fallback (unknown tail)
    return (base, None, None)


# ---- misc ----

def mem_spec_op_ok(mem, spec) -> bool:
    """
    Match mem.op against spec['op'] if provided.
    Supports:
      - alternation:  "add|and|xor"
      - negation:     "!xchg"
      - list/tuple:   ["add|and", "!xchg"] (AND across items)
    """
    want = spec.get("op", None)
    if want is None:
        return True

    val = (mem.op or "").lower()

    def _one(pattern: str) -> bool:
        neg = pattern.startswith("!")
        core = pattern[1:] if neg else pattern
        choices = [p.strip().lower() for p in core.split("|") if p.strip()]
        hit = (val in choices) if choices else (val == core.lower())
        return (not hit) if neg else hit

    if isinstance(want, str):
        return _one(want)
    if isinstance(want, (list, tuple, set)):
        return all(_one(str(p)) for p in want)
    # unknown type
    return False

def reg_match(candidate: Optional[str], pattern: Optional[str]) -> bool:
    """
    Match a register name against a pattern with optional negation and alternation.
    Behavior depends on global EXACT_REG_MATCH.
    """
    #print(f"candidate: {candidate}, pattern: {pattern}")
    if pattern is None:
        return True
    s = pattern.strip().lower()
    if not s or s in ("*", "any"):
        return True

    neg = s.startswith("!")
    if neg:
        s = s[1:]

    if EXACT_REG_MATCH:
        c = (candidate or "").strip().lower()
        opts = {t.strip().lower() for t in re.split(r"\|", s) if t.strip()}
    else:
        c = norm_reg(candidate)
        opts = {norm_reg(t.strip()) for t in re.split(r"\|", s) if t.strip()}

    opts.discard(None)
    if not opts:
        return True if neg else False

    hit = c in opts
    return (not hit) if neg else hit


    
def normalize_reg_wild(v: Optional[str]) -> Optional[str]:
    if v is None: return None
    v = v.strip().lower()
    if v in ("*","any",""): return None
    return norm_reg(v)

def bytestr_to_set(s: str) -> Set[int]:
    out=set()
    for m in re.finditer(r"\\x([0-9a-fA-F]{2})", s):
        out.add(int(m.group(1),16))
    if not out:
        for tok in re.split(r"[,\s]+", s.strip()):
            if tok:
                out.add(int(tok,16) if tok.startswith("0x") else int(tok,16))
    return out

def addr_has_bytes(addr: int, B: set) -> int:
    bs = [(addr>>(8*i))&0xff for i in range(4)]
    return sum(1 for b in bs if b in B)

def parse_kvlist(s: str) -> dict:
    """
    Parse a comma-separated list of key/operator/value tokens into a dict.

    Supported forms (spaces optional):
      key = value
      key > value
      key >= value
      key < value
      key <= value
    Examples:
      "dst=eax, src=ecx"
      "dst_disp>4, src_disp<0"
      "dst_disp>= 4, src_disp <= -8"
      "op=add|sub|xor"

    Output keys:
      '='  -> "key"
      '>'  -> "key>"
      '>=' -> "key>="
      '<'  -> "key<"
      '<=' -> "key<="

    Values are returned as raw strings (filters will coerce ints as needed).
    Keys are lowercased.
    """
    out = {}
    if not s:
        return out

    # Split on commas not inside quotes (we don't really use quotes, but be safe)
    parts = [p.strip() for p in s.split(",") if p.strip()]
    # Regex: key (alnum/underscore) + operator + value
    pat = re.compile(r"""^
        (?P<key>[A-Za-z0-9_]+)      # key
        \s*
        (?P<op><=|>=|=|<|>)         # operator
        \s*
        (?P<val>.+)                 # value (rest of token)
    $""", re.X)

    for tok in parts:
        m = pat.match(tok)
        if not m:
            # Ignore unknown/ill-formed token; caller may warn in --debug
            continue
        key = m.group("key").strip().lower()
        op  = m.group("op")
        val = m.group("val").strip()

        # Normalize key with operator
        if op == "=":
            out[key] = val
        else:
            out[f"{key}{op}"] = val

    return out

from typing import Any, Optional

def get_disp_key(d: dict, *, default: Optional[str] = None, case_insensitive: bool = False) -> Optional[str]:
    """
    Return the FIRST key in dict `d` that starts with "disp".
    - If none found, returns `default` (None by default).
    - Set `case_insensitive=True` to match case-insensitively.

    Examples:
        >>> get_disp_key({"disp": 0, "op": "mov"})
        'disp'
        >>> get_disp_key({"disp<=": 0x30, "op": "mov"})
        'disp<='
        >>> get_disp_key({"DiSp=": 4}, case_insensitive=True)
        'DiSp='
        >>> get_disp_key({"op": "mov"}) is None
        True
    """
    if case_insensitive:
        for k in d.keys():
            if isinstance(k, str) and k.lower().startswith("disp"):
                return k
        return default
    for k in d.keys():
        if isinstance(k, str) and k.startswith("disp"):
            return k
    return default


def parse_reg2reg_spec(spec: str):
    s = spec.strip().lower()
    if "->" not in s:
        raise ValueError("--reg2reg needs SRC->DST")
    a,b = s.split("->",1)
    src = a.strip()
    dst = b.strip()
    return (src if src not in ("*","any") else None, dst if dst not in ("*","any") else None)

import time

def get_duration(seconds: float) -> str:
    s = int(seconds)
    ms = int(round((seconds - s) * 1000))
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    parts = []
    if h:  parts.append(f"{h} hour" + ("s" if h != 1 else ""))
    if m:  parts.append(f"{m} min" + ("s" if m != 1 else ""))
    if sec: parts.append(f"{sec} sec")
    if not parts:  # sub-second
        parts.append(f"{ms} ms")
    return ", ".join(parts)

# ultra-simple timing helpers (optional)
def now() -> float:
    return time.time()

def elapsed_since(t0: float) -> str:
    return get_duration(time.time() - t0)


