from __future__ import annotations
import os

def _fmt_addr(addr: int, base: int | None) -> str:
    """
    Render address as either 0xADDR or 0xBASE+0xRVA (or 0xBASE-0xRVA if addr < base).
    """
    if base is None:
        return f"0x{addr:08x}"
    delta = addr - base
    if delta >= 0:
        return f"Base + 0x{delta:x}"
    return f"Base - 0x{abs(delta):x}"

def gadget_to_text(g, base: int | None = None) -> str:
    """
    Return a single-line human-readable string for a gadget.
    Includes source file (basename) when available.
    If 'base' is provided, address is printed as base+RVA form.
    """
    src = f"{os.path.basename(g.source)} " if getattr(g, "source", None) else ""
    addr_s = _fmt_addr(g.address, base)
    base_txt = f"{addr_s} # {g.text} - {src}"
    return base_txt

    s = getattr(g, "score", None)
    if s in (None, (), (None,), [], ""):
        return base_txt

    try:
        if isinstance(s, (int, float)):
            return f"{base_txt}   ; score={float(s):.2f}"
        if isinstance(s, (tuple, list)) and all(isinstance(x, (int, float)) for x in s):
            return f"{base_txt}   ; score={tuple(s)}"
    except Exception:
        pass
    return f"{base_txt}   ; score={s!r}"
