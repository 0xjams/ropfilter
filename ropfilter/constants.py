# ropfilter/constants.py
import re

REGS = ["eax","ebx","ecx","edx","esi","edi","ebp","esp"]
REGSET = set(REGS)

# Permanently banned instructions (case-insensitive)
BANNED_PATTERNS = [
    re.compile(r'^\s*clts\b', re.I),
    re.compile(r'^\s*hlt\b', re.I),
    re.compile(r'^\s*lmsw\b', re.I),
    re.compile(r'^\s*ltr\b', re.I),
    re.compile(r'^\s*lgdt\b', re.I),
    re.compile(r'^\s*lidt\b', re.I),
    re.compile(r'^\s*lldt\b', re.I),
    # control/debug/test registers
    re.compile(r'^\s*mov\s+cr\d+\s*,', re.I),
    re.compile(r'^\s*mov\s+[a-z0-9]+\s*,\s*cr\d+\b', re.I),
    re.compile(r'^\s*mov\s+dr\d+\s*,', re.I),
    re.compile(r'^\s*mov\s+[a-z0-9]+\s*,\s*dr\d+\b', re.I),
    re.compile(r'^\s*mov\s+tr\d+\s*,', re.I),
    re.compile(r'^\s*mov\s+[a-z0-9]+\s*,\s*tr\d+\b', re.I),
    # port I/O
    re.compile(r'^\s*in\s+(al|ax|eax)\s*,\s*(dx|0x[0-9a-f]+|\d+)\b', re.I),
    re.compile(r'^\s*ins(?:b|w|d)?\b', re.I),
    re.compile(r'^\s*out\s+(dx|0x[0-9a-f]+|\d+)\s*,\s*(al|ax|eax)\b', re.I),
    re.compile(r'^\s*outs(?:b|w|d)?\b', re.I),
    # invalidation / interrupts / flags
    re.compile(r'^\s*invlpg\b', re.I),
    re.compile(r'^\s*invd\b', re.I),
    re.compile(r'^\s*cli\b', re.I),
    re.compile(r'^\s*sti\b', re.I),
    re.compile(r'^\s*popf[d]?\b', re.I),
    re.compile(r'^\s*pushf[d]?\b', re.I),
    re.compile(r'^\s*int\b', re.I),
    re.compile(r'^\s*iret[d]?\b', re.I),
    re.compile(r'^\s*swapgs\b', re.I),
    re.compile(r'^\s*wbinvd\b', re.I),
]
