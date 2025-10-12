# ropfilter/models.py
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict

@dataclass
class MemOp:
    dst: Optional[str] = None
    src: Optional[str] = None
    base: Optional[str] = None
    disp: Optional[int] = None
    absolute: Optional[int] = None
    # Indicates this mem op’s value was paired with a preceding/following stack op in the same gadget
    paired: bool = False
    # Where did the paired value come from (for memwrite) or go to (for memread)?
    # One of: "reg", "mem", "stack", or None if unknown/unpaired.
    paired_src_kind: str | None = None
    # If paired from/to a register (e.g., push eax … pop [mem])
    paired_src_reg: str | None = None
    # If paired from/to memory (e.g., push [memA] … pop [memB])
    paired_src_base: str | None = None
    paired_src_disp: int | None = None
    paired_src_abs: int | None = None
    op: str | None = None
    #   inside @dataclass class MemOp:
    idx: int | None = None

@dataclass
class Pivot:
    kind: str          # xchg | mov | add | leave
    reg: Optional[str] = None
    imm: Optional[int] = None

@dataclass
class Dispatch:
    kind: str          # call | jmp
    target: str        # reg | mem | abs
    reg: Optional[str] = None
    absolute: Optional[int] = None

@dataclass
class Gadget:
    address: int
    text: str
    instrs: List[str]
    instr_count: int
    ret_imm: Optional[int]
    stack_delta: Optional[int]
    reg2reg: List[Tuple[str,str,str]] = field(default_factory=list) # (src,dst,kind)
    memreads: List[MemOp] = field(default_factory=list)
    memwrites: List[MemOp] = field(default_factory=list)
    zero: List[str] = field(default_factory=list)
    arith: List[Dict] = field(default_factory=list)
    pops: List[str] = field(default_factory=list)
    pivot: List[Pivot] = field(default_factory=list)
    dispatch: List[Dispatch] = field(default_factory=list)
    clobbers: List[str] = field(default_factory=list)
    score: Optional[float] = None
    source: Optional[str] = None   # file path this gadget came from

