
# ropfilter
A tool that was developed during my OSED course.

ropfilter operates on [rp++](https://github.com/0vercl0k/rp) output files.

# usage
```
usage: ropfilter [-h] -f FILE [FILE ...] [--base-addr BASE_ADDR] [--addr-no-bytes ADDR_NO_BYTES] [--max-instr MAX_INSTR] [--ret-only] [--retn RETN] [--protect-stack] [--max-stack-delta MAX_STACK_DELTA] [--stable-dst] [--stable-src] [--exact-reg]
                 [--strict-mem] [--safe-enable] [--reg2reg REG2REG] [--memread MEMREAD] [--memwrite MEMWRITE] [--arith ARITH] [--call-reg CALL_REG] [--call-abs CALL_ABS] [--call-mem CALL_MEM] [--pivot] [--pivot-kind {xchg,mov,add,leave}]
                 [--pivot-reg PIVOT_REG] [--pivot-imm PIVOT_IMM] [--pop-seq POP_SEQ] [--avoid-clobber AVOID_CLOBBER] [--require-writes REQUIRE_WRITES] [--avoid-memref AVOID_MEMREF] [--chain] [--chain-max-steps CHAIN_MAX_STEPS]
                 [--chain-allow CHAIN_ALLOW] [--chain-limit CHAIN_LIMIT] [--reg-map REG_MAP] [--pop-map [N/REGS]] [--solve-json SOLVE_JSON] [--solve-file SOLVE_FILE] [--solve-max-solutions SOLVE_MAX_SOLUTIONS] [--best-last] [--limit LIMIT]
                 [--out {text,json,python}] [--debug] [--debug-file PATH]

Filter and chain ROP gadgets from rp++-style dumps.

options:
  -h, --help            show this help message and exit

Input:
  -f, --file FILE [FILE ...]
                        Path(s) to rp++-style gadget text file(s) (default: None)
  --base-addr BASE_ADDR
                        Base address for 'Base + 0x...' formatting (default: None)

Core filters & limits:
  --addr-no-bytes ADDR_NO_BYTES
                        Comma-separated bad bytes not allowed in gadget address (e.g., '00,0a,0d,ff'). (default: None)
  --max-instr MAX_INSTR
                        Maximum instruction count per gadget (default: None)
  --ret-only            Require bare 'ret' (retn 0) (default: False)
  --retn RETN           Require 'retn N' with immediate N return retn with imm < N (default: None)
  --protect-stack       drop gadgets with pushes more than pops (default: False)
  --max-stack-delta MAX_STACK_DELTA
                        Maximum allowed stack delta (default: None)
  --stable-dst          If set, reject gadgets where the matched DST register is overwritten later with a different value (smart, order-aware). Default: off. (default: False)
  --stable-src          Reject gadgets where the source register is overwritten *before* the matched instruction. (default: False)
  --exact-reg           Match exact register names (no sub-register aliasing). (default: False)
  --strict-mem          Reject any gadget that uses absolute memory reference [0x...]. (default: False)
  --safe-enable         Enable a safe preset: --protect-stack --stable-dst --stable-src --strict-mem --exact-reg (default: False)

Register transfers:
  --reg2reg REG2REG     Filter gadgets that move/copy between registers. Format: 'SRC->DST' where SRC/DST are REGPATs (e.g., 'eax|ecx->!ebx'). May be provided multiple times. (default: [])

Memory operations (memread/memwrite):
  --memread MEMREAD     Match memory reads into registers. Repeatable. Format: dst=REGPAT, base=REGPAT, abs=0xADDR, op=OP, disp=INT, disp>INT, disp>=INT, disp<INT, disp<=INT (default: [])
  --memwrite MEMWRITE   Match memory writes from registers. Repeatable. Format: src=REGPAT, base=REGPAT, abs=0xADDR, op=OP, disp=INT, disp>INT, disp>=INT, disp<INT, disp<=INT (default: [])

Arithmetic / logical operations (--arith):
  --arith ARITH         Match arithmetic/logical ops. Repeatable. Parsed as key-value list. Keys: op=add|sub|xor|or|and|adc|sbb|imul|neg|inc|dec|lea|xadd|... dst=REGPAT, src=REGPAT, imm=INT Memory participants (optional): dst_base=REGPAT,
                        dst_abs=ADDR, dst_disp=INT | dst_disp>INT | dst_disp>=INT | dst_disp<INT | dst_disp<=INT src_base=REGPAT, src_abs=ADDR, src_disp=INT | src_disp>INT | src_disp>=INT | src_disp<INT | src_disp<=INT (default: [])

Dispatch & pivot:
  --call-reg CALL_REG   Require call/jmp via register (e.g., 'eax') (default: None)
  --call-abs CALL_ABS   Require call/jmp absolute address (int/hex) (default: None)
  --call-mem CALL_MEM   Require call/jmp [REG] style (base register) (default: None)
  --pivot               Require gadget to be a stack pivot (default: False)
  --pivot-kind {xchg,mov,add,leave}
                        Restrict pivot kind (default: None)
  --pivot-reg PIVOT_REG
                        Pivot controlling register (e.g., 'eax') (default: None)
  --pivot-imm PIVOT_IMM
                        Immediate for arithmetic pivots (default: None)

Sequence / clobber constraints:
  --pop-seq POP_SEQ     Require a subsequence of pops (comma-separated regs, exact order) (default: None)
  --avoid-clobber AVOID_CLOBBER
                        Drop gadgets that clobber any of these registers (default: None)
  --require-writes REQUIRE_WRITES
                        Require that all these registers are written by the gadget (default: None)
  --avoid-memref AVOID_MEMREF
                        Avoid gadgets that contain memory references using specified base registers. Patterns: * → avoid all memory references eax → avoid memory references using eax as the base eax|ebx → avoid memory references using eax or ebx as
                        the base !eax|ebx → allow ONLY eax or ebx as base (avoid all others) Special rule: when using '*', explicit base constraints from other filters (base= in --memread/--memwrite, or src_base=/dst_base= in --arith) override the
                        avoidance for the specified base(s). (default: None)

Chaining & maps:
  --chain               Enable chain search when single gadget fails (default: False)
  --chain-max-steps CHAIN_MAX_STEPS
                        Max gadgets in a synthesized chain (default: 3). (default: 3)
  --chain-allow CHAIN_ALLOW
                        Allowed temporary registers during chaining (default: all GPRs except esp). (default: None)
  --chain-limit CHAIN_LIMIT
                        Max number of synthesized chains to print (default: 10). (default: 10)
  --reg-map REG_MAP     Print register transfer map instead of gadgets (default: None)
  --pop-map [N/REGS]    Print POP gadgets per register. Forms: N, N/REG or N/REG1,REG2, or just REG1,REG2; empty => top 5 all. (default: None)

Constraint solver (JSON/YAML):
  --solve-json SOLVE_JSON
                        Inline JSON solve spec. (default: None)
  --solve-file SOLVE_FILE
                        Path to JSON/YAML spec. YAML requires PyYAML. (default: None)
  --solve-max-solutions SOLVE_MAX_SOLUTIONS
                        Maximum number of solutions from the solver (default: 10)

Output & ranking:
  --best-last           Print highest-ranked gadgets last (default: False)
  --limit LIMIT         Limit number of printed gadgets (default: None)
  --out {text,json,python}
                        Output format (default: text)
  --debug               Verbose debug logs (default: False)
  --debug-file PATH     Write JSONL debug trace of the solve process to PATH (optional). (default: None)

Examples: # Simple reg move: -f app_rop.txt --reg2reg 'esp->eax' # Memory read/write with displacement constraints: --memread 'dst=eax,base=ecx,disp>=0x10,disp<0x40' --memwrite 'src=edx,base=esi,disp> = 0' # Arithmetic with memory participants

(dst_mem/src_mem): --arith 'op=add,dst=esi,src_base=eax,src_disp<=0' # Exact register names (eax != ax != al) everywhere: --exact-reg # Solver (JSON/YAML file), find regx/regy s.t. reachability and a memwrite hold: --solve-file spec.yaml
```
# Key Flags
## --reg2reg
**Locate gadgets that transfer src reg to dst reg**
### Find gadgets that transfer eax to ecx
```

└─# python3 -m ropfilter --safe-enable --addr-no-bytes 0x00 -f libeay32IBM019.dll_rop.txt --reg2reg 'eax->ecx'
0x1002f6fa # xchg eax, ecx ; nop ; add byte [eax], al ; add byte [eax+0x57], dl ; call edx - libeay32IBM019.dll_rop.txt 
0x1002f4d4 # xchg eax, ecx ; nop ; add byte [eax], al ; add byte [edi-0x7d], dl ; ret - libeay32IBM019.dll_rop.txt 
0x10057baf # xchg eax, ecx ; or dword [ebx], eax ; add byte [ebx+0x6a560cc4], al ; call dword [edi-0x18] - libeay32IBM019.dll_rop.txt 
0x10057934 # xchg eax, ecx ; pop edi ; pop esi ; or eax, 0xffffffff ; pop ebx ; ret - libeay32IBM019.dll_rop.txt 
0x1002ab13 # xchg eax, ecx ; std ; call dword [esi-0x18] - libeay32IBM019.dll_rop.txt 

```

### Find where eax can go to
```

└─# python3 -m ropfilter --safe-enable --addr-no-bytes 0x00 -f libeay32IBM019.dll_rop.txt --reg2reg 'eax->*'              
0x10077702 # adc byte [eax+esi-0x18], dh ; xchg eax, esi ; lds edi, esp ; jmp dword [0x00000fff] - libeay32IBM019.dll_rop.txt 
0x10054158 # adc byte [eax-0x18], dl ; xchg eax, ecx ; inc eax ; add byte [eax], al ; add esp, 0x08 ; ret - libeay32IBM019.dll_rop.txt 
0x10040c6a # adc byte [eax-0x26], ch ; add byte [eax], al ; add byte [edi], cl ; xchg eax, esp ; ret - libeay32IBM019.dll_rop.txt 
0x10083f1e # adc byte [eax-0x50], ch ; xchg eax, ebp ; or edx, dword [eax] ; call esi - libeay32IBM019.dll_rop.txt 
0x10083eef # adc byte [eax-0x50], ch ; xchg eax, ebp ; or edx, dword [eax] ; mov dword [0x100e3c30], 0x00000001 ; call esi - libeay32IBM019.dll_rop.txt 
0x100445c5 # adc byte [edi], cl ; xchg eax, ebp ; rol byte [ebp+0x330375c0], 0xffffffc0 ; ret - libeay32IBM019.dll_rop.txt 
0x100408da # add bh, bh ; inc esi ; push eax ; pop esi ; ret - libeay32IBM019.dll_rop.txt 
0x10044bda # add bl, ch ; dec ebx ; lea edx, dword [eax+eax*2] ; mov eax, dword [0x100d80d0+edx*8] ; add esp, 0x20 ; ret - libeay32IBM019.dll_rop.txt
```

### Find if eax can go to ecx or edx - print best gadget last
```

└─# python3 -m ropfilter --safe-enable --addr-no-bytes 0x00 -f libeay32IBM019.dll_rop.txt --best-last --reg2reg 'eax->ecx|edx' 
0x1002f6f7 # sbb byte [edx-0x75], dl ; xchg eax, ecx ; nop ; add byte [eax], al ; add byte [eax+0x57], dl ; call edx - libeay32IBM019.dll_rop.txt 
0x1002f6f3 # orps xmm0,  [ebx-0x74ade73e] ; xchg eax, ecx ; nop ; add byte [eax], al ; add byte [eax+0x57], dl ; call edx - libeay32IBM019.dll_rop.txt 
0x1003f570 # xchg eax, edx ; add byte [eax], al ; add byte [edi+0x2b], dh ; movzx eax, byte [eax+0x1003f798] ; jmp dword [0x1003f744+eax*4] - libeay32IBM019.dll_rop.txt 
0x1002f6fa # xchg eax, ecx ; nop ; add byte [eax], al ; add byte [eax+0x57], dl ; call edx - libeay32IBM019.dll_rop.txt
0x1004f2a1 # xchg eax, edx ; add eax, dword [eax] ; add esp, 0x0c ; ret - libeay32IBM019.dll_rop.txt 
0x1004f241 # xchg eax, edx ; add eax, dword [eax] ; add esp, 0x0c ; ret - libeay32IBM019.dll_rop.txt 
0x1004ebd7 # xchg eax, edx ; add byte [eax], al ; add esp, 0x04 ; ret - libeay32IBM019.dll_rop.txt 
0x10044c7d # lea edx, dword [eax+eax*2] ; mov eax, dword [0x100d80d4+edx*8] ; add esp, 0x20 ; ret - libeay32IBM019.dll_rop.txt 
0x10044bdd # lea edx, dword [eax+eax*2] ; mov eax, dword [0x100d80d0+edx*8] ; add esp, 0x20 ; ret - libeay32IBM019.dll_rop.txt 
0x10021a5a # xchg eax, edx ; ret - libeay32IBM019.dll_rop.txt 

```

### Find where eax can go to except ecx and edx
```

└─# python3 -m ropfilter --safe-enable --addr-no-bytes 0x00 -f libeay32IBM019.dll_rop.txt --best-last --reg2reg 'eax->!ecx|edx' 
0x10083eec # xchg eax, esp ; cmc ; or dword [eax], edx ; push 0x100b95b0 ; mov dword [0x100e3c30], 0x00000001 ; call esi - libeay32IBM019.dll_rop.txt 
0x10049312 # sub ecx, dword [edi] ; mov dh, 0x80 ; pushad ; xchg eax, ebx ; add al, 0x10 ; jmp dword [0x10049350+eax*4] - libeay32IBM019.dll_rop.txt 
0x1005b415 # xchg eax, esp ; ret - libeay32IBM019.dll_rop.txt 
0x1004edc7 # lea eax, dword [eax+eax-0x01] ; ret - libeay32IBM019.dll_rop.txt 
0x10040c71 # xchg eax, esp ; ret - libeay32IBM019.dll_rop.txt 
0x1003a003 # xchg eax, esp ; ret - libeay32IBM019.dll_rop.txt 
[time] total: 325 ms

```

### Find where eax can go to except ecx and edx and avoid gadgets that modify esp and as always print best gadget last
```

└─# python3 -m ropfilter --safe-enable --addr-no-bytes 0x00 -f libeay32IBM019.dll_rop.txt --best-last --reg2reg 'eax->!ecx|edx' --avoid-clobber esp
0x100408dd # push eax ; pop esi ; ret - libeay32IBM019.dll_rop.txt 
0x1003b534 # xchg eax, ebp ; ror dword [ecx-0x74a1dfba], 0xffffffc1 ; ret - libeay32IBM019.dll_rop.txt 
0x10035957 # xchg eax, ebp ; ror dword [ecx-0x74a1f3ba], 0xffffffc1 ; ret - libeay32IBM019.dll_rop.txt 
0x10035917 # xchg eax, ebp ; ror dword [ecx-0x74a1fbba], 0xffffffc1 ; ret - libeay32IBM019.dll_rop.txt 
0x1002ade5 # xchg eax, edi ; test dword [edx], 0x10c48300 ; ret - libeay32IBM019.dll_rop.txt 
0x1004edc7 # lea eax, dword [eax+eax-0x01] ; ret - libeay32IBM019.dll_rop.txt 
[time] total: 335 ms


```
## --memread
**Locate gadgets that read memory value pointed to by base reg +- displacment into dst reg**

### Find gadgets that read memory location pointed to by eax with displacment <= 0x20 and write the memory value back to eax, using only operations mov|pop|xchg and as always print best gadget last

```
└─# python3 -m ropfilter --safe-enable --addr-no-bytes 0x00 -f libeay32IBM019.dll_rop.txt --best-last --avoid-clobber esp --memread 'base=eax,dst=eax,op=mov|pop|xchg,disp<=0x20'
0x1004427e # mov edx, dword [eax+0x08] ; mov eax, dword [eax+0x04] ; mov dword [esp+0x08], edx ; mov dword [esp+0x04], ecx ; jmp eax - libeay32IBM019.dll_rop.txt 
0x1006ad07 # mov eax, dword [eax+0x08] ; pop esi ; mov dword [esp+0x08], edx ; jmp eax - libeay32IBM019.dll_rop.txt 
0x1007565e # mov eax, dword [eax+0x04] ; call eax - libeay32IBM019.dll_rop.txt 
0x1004b224 # mov eax, dword [eax+0x10] ; ret - libeay32IBM019.dll_rop.txt 
0x1004014e # mov eax, dword [eax+0x08] ; ret - libeay32IBM019.dll_rop.txt 
0x10035924 # mov eax, dword [eax+0x0c] ; ret - libeay32IBM019.dll_rop.txt 
0x1002bcd3 # mov eax, dword [eax+0x20] ; ret - libeay32IBM019.dll_rop.txt 
0x1001d4b4 # mov eax, dword [eax] ; ret - libeay32IBM019.dll_rop.txt 
[time] total: 335 ms

```
### Find gadgets that read memory pointed to by ecx into any reg and as always print best gadget last

```
└─# python3 -m ropfilter --safe-enable --addr-no-bytes 0x00 -f libeay32IBM019.dll_rop.txt --best-last --avoid-clobber esp --memread 'base=ecx'  
0x100391a6 # mov eax, dword [ecx] ; ret - libeay32IBM019.dll_rop.txt 
0x1002bc6a # mov eax, dword [ecx+0x0c] ; ret - libeay32IBM019.dll_rop.txt 
0x1004bcc4 # add ecx, dword [ecx-0x74a0efba] ; ret - libeay32IBM019.dll_rop.txt 


```

## --memwrite
**Locate gadgets that write src reg value into memory location pointed by base reg +- displacment**

### Find gadgets that write eax to the memory location pointed to by ebp with any displacment and using any operation and as always print best gadget last

```
└─# python3 -m ropfilter --safe-enable --addr-no-bytes 0x00 -f libeay32IBM019.dll_rop.txt --best-last --avoid-clobber esp --memwrite 'base=ebp,src=eax'     
0x1001dc39 # mov eax, dword [ebp+0x00] ; mov dword [ebp+0x04], eax ; mov dword [ebp+0x0c], 0x00000000 ; pop ebp ; pop ebx ; ret - libeay32IBM019.dll_rop.txt 
0x10088fa9 # mov dword [ebp-0x04], 0xfffffffe ; mov dword [ebp-0x08], eax ; lea eax, dword [ebp-0x10] ; mov dword [fs:0x00000000], eax ; ret - libeay32IBM019.dll_rop.txt 
0x1008286f # mov dword [ebp+0x00], eax ; pop ebp ; mov eax, 0x00000001 ; pop ebx ; ret - libeay32IBM019.dll_rop.txt 
0x1008284c # mov dword [ebp+0x00], eax ; pop ebp ; mov eax, 0x00000002 ; pop ebx ; ret - libeay32IBM019.dll_rop.txt 
0x1006b133 # or dword [ebp-0x3b7c0003], eax ; adc al, 0x5e ; xor eax, eax ; pop ebp ; ret - libeay32IBM019.dll_rop.txt 
0x1003f22d # mov dword [ecx+0x0c], eax ; mov dword [ebp+0x0c], eax ; pop ebp ; pop ebx ; ret - libeay32IBM019.dll_rop.txt 
0x1001dc3c # mov dword [ebp+0x04], eax ; mov dword [ebp+0x0c], 0x00000000 ; pop ebp ; pop ebx ; ret - libeay32IBM019.dll_rop.txt 
0x10088fb0 # mov dword [ebp-0x08], eax ; lea eax, dword [ebp-0x10] ; mov dword [fs:0x00000000], eax ; ret - libeay32IBM019.dll_rop.txt 
0x1007484d # or dword [ebp+0x5f0575db], eax ; xor eax, eax ; pop ebx ; ret - libeay32IBM019.dll_rop.txt 
0x1003f230 # mov dword [ebp+0x0c], eax ; pop ebp ; pop ebx ; ret - libeay32IBM019.dll_rop.txt 
[time] total: 343 ms

```

## --arith 
**Locate gadgets that perform arithmatic operation on regs or memory location stored in regs

### Find gadgets add or sub ecx to eax

```
─# python3 -m ropfilter --safe-enable --addr-no-bytes 0x00 -f libeay32IBM019.dll_rop.txt  --avoid-clobber esp --best-last --arith 'dst=eax,src=ecx,op=add|sub'
0x10064e61 # pop edi ; pop esi ; pop ebp ; sub eax, ecx ; pop ebx ; ret - libeay32IBM019.dll_rop.txt  
0x10064e64 # sub eax, ecx ; pop ebx ; ret - libeay32IBM019.dll_rop.txt 
0x10064d1a # sub eax, ecx ; pop ebp ; ret - libeay32IBM019.dll_rop.txt 
0x10064cd2 # sub eax, ecx ; pop ebp ; ret - libeay32IBM019.dll_rop.txt 
0x1004a7b6 # sub eax, ecx ; pop ebx ; ret - libeay32IBM019.dll_rop.txt 
0x1001d0f0 # add eax, ecx ; ret - libeay32IBM019.dll_rop.txt 
[time] total: 411 ms

```

### Find gadgets that add dl to memory location pointed to by eax 

```
└─# python3 -m ropfilter --safe-enable --addr-no-bytes 0x00 -f libeay32IBM019.dll_rop.txt  --avoid-clobber esp --best-last --arith 'dst_base=eax,src=dl,op=add'
0x100421cf # add byte [eax+0x56], dl ; call dword [esp+0x54] - libeay32IBM019.dll_rop.txt 
0x10042193 # add byte [eax+0x56], dl ; call dword [esp+0x50] - libeay32IBM019.dll_rop.txt 
0x1003a364 # add byte [eax+0x52], dl ; call dword [0x100d5054] - libeay32IBM019.dll_rop.txt 
0x1002f6fe # add byte [eax+0x57], dl ; call edx - libeay32IBM019.dll_rop.txt 
0x10079d87 # add byte [eax-0x18], dl ; xor ah, byte [ebx-0x04] ; inc dword [ebx+0x5e5f08c4] ; pop ebp ; ret - libeay32IBM019.dll_rop.txt 
[time] total: 413 ms

```

### Find gadgets that read memory pointed to by eax add it to to edx

```
─# python3 -m ropfilter --safe-enable --addr-no-bytes 0x00 -f libeay32IBM019.dll_rop.txt  --avoid-clobber esp --best-last --arith 'src_base=eax,dst=edx,op=add'
0x1003fbff # adc byte [edi-0x05], ch ; add edx, dword [eax] ; xchg bl, bh ; add edx, dword [eax] ; ret - libeay32IBM019.dll_rop.txt 
0x1003c3a2 # add edx, dword [eax] ; mov al, dl ; add edx, dword [eax] ; aaa ; ret - libeay32IBM019.dll_rop.txt 
0x1003c3a1 # rol byte [ebx], 0x00000010 ; mov al, dl ; add edx, dword [eax] ; aaa ; ret - libeay32IBM019.dll_rop.txt 
0x1003fc02 # add edx, dword [eax] ; xchg bl, bh ; add edx, dword [eax] ; ret - libeay32IBM019.dll_rop.txt 
0x1003c3a4 # mov al, dl ; add edx, dword [eax] ; aaa ; ret - libeay32IBM019.dll_rop.txt 
0x1003fc04 # xchg bl, bh ; add edx, dword [eax] ; ret - libeay32IBM019.dll_rop.txt 
0x1003c3a6 # add edx, dword [eax] ; aaa ; ret - libeay32IBM019.dll_rop.txt 
0x1003a246 # add edx, dword [eax] ; mov eax, 0x00000001 ; ret - libeay32IBM019.dll_rop.txt 
0x10064fd6 # add edx, dword [eax-0x18] ; ret - libeay32IBM019.dll_rop.txt 
0x1003fc06 # add edx, dword [eax] ; ret - libeay32IBM019.dll_rop.txt 
```

### Find gadgets that perform operation neg|xor

```
─# python3 -m ropfilter --safe-enable --addr-no-bytes 0x00 -f libeay32IBM019.dll_rop.txt  --avoid-clobber esp --best-last --arith 'op=neg|xor'


0x10033951 # xor byte [ecx+0x0a], 0x00000010 ; ret - libeay32IBM019.dll_rop.txt 
0x10032f43 # neg eax ; ret - libeay32IBM019.dll_rop.txt 
0x10031a2e # neg eax ; ret - libeay32IBM019.dll_rop.txt 
0x1001b2b6 # xor byte [esi+0x5d], bl ; ret - libeay32IBM019.dll_rop.txt 
0x1001b2b1 # xor bl, byte [esi+0x5d] ; ret - libeay32IBM019.dll_rop.txt 
0x1001aec4 # xor byte [esi+0x5d], bl ; ret - libeay32IBM019.dll_rop.txt 
0x10011cb6 # xor byte [esi+0x5d], bl ; ret - libeay32IBM019.dll_rop.txt 
0x10011cb1 # xor bl, byte [esi+0x5d] ; ret - libeay32IBM019.dll_rop.txt 
0x10011b64 # xor byte [esi+0x5d], bl ; ret - libeay32IBM019.dll_rop.txt 
[time] total: 406 ms

```



-----------------------------------------------
**Now the action starts**
-----------------------------------------------
## --chain
**if there is not one gadget to perform the requested action, --chain will try to chain several gadgets to perform the operation.**

### There is no gadget that transfer ebx -> ebp without modifing esp

```
└─# python3 -m ropfilter --safe-enable --addr-no-bytes 0x00 -f libeay32IBM019.dll_rop.txt  --avoid-clobber esp --reg2reg 'ebx->ebp'        
[time] total: 335 ms


# don't worry try the --chain
└─# python3 -m ropfilter --safe-enable --addr-no-bytes 0x00 -f libeay32IBM019.dll_rop.txt  --avoid-clobber esp --reg2reg 'ebx->ebp' --chain
[chain] synthesized candidate chains (best first):
0x1001ee9e  ->  0x10035917
    mov eax, ebx ; pop ebx ; ret  ->  xchg eax, ebp ; ror dword [ecx-0x74a1fbba], 0xffffffc1 ; ret
0x1001ee9e  ->  0x10035957
    mov eax, ebx ; pop ebx ; ret  ->  xchg eax, ebp ; ror dword [ecx-0x74a1f3ba], 0xffffffc1 ; ret
0x1001ee9e  ->  0x1003b534
    mov eax, ebx ; pop ebx ; ret  ->  xchg eax, ebp ; ror dword [ecx-0x74a1dfba], 0xffffffc1 ; ret
0x1001ee9e  ->  0x100445c7
    mov eax, ebx ; pop ebx ; ret  ->  xchg eax, ebp ; rol byte [ebp+0x330375c0], 0xffffffc0 ; ret
0x1001ee9e  ->  0x100495f5
    mov eax, ebx ; pop ebx ; ret  ->  xchg eax, ebp ; ror dword [ecx-0x74a1f3ba], 0xffffffc1 ; ret
0x1001ee9e  ->  0x10067f38
    mov eax, ebx ; pop ebx ; ret  ->  xchg eax, ebp ; ror dword [ecx-0x74a1a0fa], 0xffffffc1 ; ret
0x1001ee9e  ->  0x10030af7
    mov eax, ebx ; pop ebx ; ret  ->  xchg eax, ebp ; test al, 0xfe ; inc dword [ebx+0x5e5f0cc4] ; ret
0x1001ee9e  ->  0x100445c5
    mov eax, ebx ; pop ebx ; ret  ->  adc byte [edi], cl ; xchg eax, ebp ; rol byte [ebp+0x330375c0], 0xffffffc0 ; ret
0x1001ee9e  ->  0x1001104f
    mov eax, ebx ; pop ebx ; ret  ->  xchg eax, ebp ; xor byte [esi+0x09], dh ; adc byte [ebx], dh ; lds esi,  [ebx] ; ret
0x1001ee9e  ->  0x100445c3
    mov eax, ebx ; pop ebx ; ret  ->  cmp ecx, dword [esi] ; adc byte [edi], cl ; xchg eax, ebp ; rol byte [ebp+0x330375c0], 0xffffffc0 ; ret
[time] total: 383 ms
```

## --reg-map
**This is very useful flag to run at the begining, it will print reg transfer map for all regs combine it with --chain to boost the power.**

### Print reg map for all regs, max rop gadget per reg -> reg is 1 and look for chains too

```
└─# python3 -m ropfilter --safe-enable --addr-no-bytes 0x00 -f libeay32IBM019.dll_rop.txt  --avoid-clobber esp --reg-map 1 --chain

....output too long....example for esp only....

=== esp ===

== esp -> eax ==
  - CHAIN (2 steps):
      * 0x100408d6 # push esp ; pop esi ; ret - libeay32IBM019.dll_rop.txt 
      * 0x100203cd # mov eax, esi ; pop esi ; ret - libeay32IBM019.dll_rop.txt 

== esp -> ebx ==
  - CHAIN (2 steps):
      * 0x100408d6 # push esp ; pop esi ; ret - libeay32IBM019.dll_rop.txt 
      * 0x1003f6ec # push esi ; and byte [ebx+0x5e5f0842], cl ; pop ebx ; ret - libeay32IBM019.dll_rop.txt 

== esp -> ecx ==
  - CHAIN (3 steps):
      * 0x100408d6 # push esp ; pop esi ; ret - libeay32IBM019.dll_rop.txt 
      * 0x100203cd # mov eax, esi ; pop esi ; ret - libeay32IBM019.dll_rop.txt 
      * 0x1001d8bd # xchg eax, ecx ; neg eax ; sbb eax, eax ; neg eax ; ret - libeay32IBM019.dll_rop.txt 

== esp -> edx ==
  - CHAIN (3 steps):
      * 0x100408d6 # push esp ; pop esi ; ret - libeay32IBM019.dll_rop.txt 
      * 0x100203cd # mov eax, esi ; pop esi ; ret - libeay32IBM019.dll_rop.txt 
      * 0x10021a5a # xchg eax, edx ; ret - libeay32IBM019.dll_rop.txt 

== esp -> esi ==
  - 0x100408d6 # push esp ; pop esi ; ret - libeay32IBM019.dll_rop.txt 

== esp -> edi ==
  - 0x10045df9 # push esp ; and al, 0x10 ; mov dword [edx], ecx ; pop edi ; ret - libeay32IBM019.dll_rop.txt 

== esp -> ebp ==
  - CHAIN (2 steps):
      * 0x100408d6 # push esp ; pop esi ; ret - libeay32IBM019.dll_rop.txt 
      * 0x1003f0e5 # push esi ; adc al, 0x03 ; ror dword [ecx+0x5e5f0055], 1 ; pop ebp ; ret - libeay32IBM019.dll_rop.txt 

```
## --solve-file
**The tool can read yaml file that define reg variables that have set of constrains similar to the flags mentioned above, the tool will try to solve the reg variables and detect what set of regs comply with all the defined constrains**

for example in typical rop chain we need a reg that points to the VirtualAlloc skeleton, lets call it "base" we also need a reg that can dereference memory location lets call it "func". we need them to satisfy the following constrains:
1. reg2reg: esp->base and avoid modifying esp
2. reg2reg: base->esp
3. memread: base=func, dst=func
4. memwrite: base=base, src=func
5. base and func cannot be the same reg
6. we need to be able to pop to func

This constrains can be translated to the following yaml file
```
vars: [base, func]

constraints:
  - reg2reg: { src: esp, dst: base, clobber: [esp] }      # base := esp
  - reg2reg: { src: base, dst: esp }   

  - any_of:
    - memread:  { dst: func, base: func , clobber: [esp,base] ,disp=: 0, op: "mov|pop|xchg"}
    - memread:  { dst: func, base: func , clobber: [esp,base] ,disp>=: 0, op: "mov|pop|xchg"}
    - memread:  { dst: func, base: func , clobber: [esp,base] ,disp<=: 0, op: "mov|pop|xchg"}

  - any_of:
    - memwrite:  { src: func, base: base , clobber: [esp,base] ,disp=: 0, op: "mov|pop|xchg"}
    - memwrite:  { src: func, base: base , clobber: [esp,base] ,disp=: 4, op: "mov|pop|xchg"} 
    - memwrite:  { src: func, base: base , clobber: [esp,base] ,disp=: -4, op: "mov|pop|xchg"} 
    - memwrite:  { src: func, base: base , clobber: [esp,base] ,disp>=: -0x20, op: "mov|pop|xchg"} 
    - memwrite:  { src: func, base: base , clobber: [esp,base] ,disp<=: 0x20, op: "mov|pop|xchg"}  

  - pop: { dst: func, clobber: [esp,base] } 
  - distinct: [base, func]
  - in:     { var: base, set: [eax, ebx, ecx, edx, esi, edi, ebp] }
  - in:     { var: func, set: [eax, ebx, ecx, edx, esi, edi, ebp] }


# ---- Global options & constraints ----
#parsed by ropfilter.solver._apply_global_spec_overrides()
options:
  exact_reg: true          # eax ≠ ax ≠ al -> must also be added in cmd - or use --safe-enable
  stable_dst: true         # enable smart overwrite protection during solving on dst
  stable_src: true         # enable smart overwrite protection during solving on src
  avoid_memref: "*"        # reject gadgets with memref to other registers than base in memread|memwrite filters
  
limits:
  max_instr: 5            # max instructions per gadget keep it similar to rop++ -r 
  max_solutions: 1        # max solutions to solve
  retn: 0x20               # accept only gadgets with ret or retn N < 0x20
  bad_bytes: [0x00]

memory:
  strict: true             # reject absolute [0x...]
  protect_stack: true
```
Now lets ask ropfilter to solve the file for us.
```
took 1 sec
=== Solution 1 ===
Bindings:
  base = ebx
  func = eax
Witnesses:
  any_of[2]/choice1:
    memread[2]:
      Path 1:
        - 0x1001d4b4 # mov eax, dword [eax] ; ret - libeay32IBM019.dll_rop.txt 
  any_of[3]/choice1:
    memwrite[3]:
      Path 1:
        - 0x1008a362 # xchg dword [ebx], eax ; ret - libeay32IBM019.dll_rop.txt 
  pop[4]:
    - 0x10048d5b # pop eax ; ret - libeay32IBM019.dll_rop.txt 
  reg2reg[0]:
    Path 1:
      - 0x100408d6 # push esp ; pop esi ; ret - libeay32IBM019.dll_rop.txt 
      - 0x100203cd # mov eax, esi ; pop esi ; ret - libeay32IBM019.dll_rop.txt 
      - 0x1004931e # xchg eax, ebx ; add al, 0x10 ; mov eax, 0x00000006 ; ret - libeay32IBM019.dll_rop.txt 
  reg2reg[1]:
    Path 1:
      - 0x1001ee9e # mov eax, ebx ; pop ebx ; ret - libeay32IBM019.dll_rop.txt 
      - 0x1003a003 # xchg eax, esp ; ret - libeay32IBM019.dll_rop.txt 

--------------------------------------------------------
[time] total: 1 sec


```
I would not over complicate the yaml file, keep it simple to avoid hitting huge key space and take forever to solve, and always modify it based on the context you have to avoid false negative



