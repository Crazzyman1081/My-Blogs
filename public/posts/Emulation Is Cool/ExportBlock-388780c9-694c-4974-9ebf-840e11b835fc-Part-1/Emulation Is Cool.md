---
date: "2025-12-31"
description: "A Simpler way to \"reimplement\" Functions"
image: "../../../emulation.png"
---

# Emulation is cool

so recently I found a cool way to emulate single functions from any binary
basically using unicorn its possible to emulate functions if we know how things are passed into the function using registers or from the stack

this is a solve to a crackmes.one chall

here is the link if you wanna try it out - [https://crackmes.one/crackme/694a6c2a0c16072f40f5a346](https://crackmes.one/crackme/694a6c2a0c16072f40f5a346)

basically we can create a executable chunk and fill it with the function's bytecode and in this case populate the stack by looking at the disasm of how the func is called

in this particular case there was a sub function inside the function i wanted to emulate too
and for the return value of the func we log the RDX register which holds the ret value in this case

also had to deal with a global data member the function was using which was a xor key we can just add that to the base with same offset as the binary

so goodbye to reimplementing hash funcs in python 👋🏻
might also be useful in some pwn challs


> [!NOTE]
> I am adding this later to this blog… this was written way earlier so its missing pictures for refrences sorry!


Here is the solve.py

```python
from unicorn import *
from unicorn.x86_const import *

def format_key(dwords):
    return "-".join(f"{x & 0xffffffff:08X}" for x in dwords)

BASE        = 0x140000000
FUNC_ADDR   = BASE + 0x17E0
SUB_ADDR    = BASE + 0x1A50
DATA_ADDR   = BASE + 0x4AA0

STOP_ADDR   = BASE + 0x1A37 

STACK_BASE  = 0x3000000
STACK_SIZE  = 0x40000

INPUT_ADDR  = 0x5000000
OUTPUT_ADDR = 0x5001000
TEB_ADDR    = 0x6000000 

def load_hex_file(path):
    with open(path, "r") as f:
        hex_data = "".join(line.strip() for line in f)
        return bytes.fromhex(hex_data)

try:
    func_code = load_hex_file("func_17e0.hex")
    sub_code  = load_hex_file("func_1a50.hex")
except FileNotFoundError:
    print("[-] Error: Hex files not found.")
    exit()

mu = Uc(UC_ARCH_X86, UC_MODE_64)

mu.mem_map(BASE, 0x300000)           
mu.mem_map(STACK_BASE, STACK_SIZE)   
mu.mem_map(INPUT_ADDR, 0x1000)       
mu.mem_map(OUTPUT_ADDR, 0x1000)      
mu.mem_map(TEB_ADDR, 0x1000)           

mu.mem_write(TEB_ADDR, b'\x00' * 0x1000)
mu.mem_write(TEB_ADDR + 0x28, b'\xEF\xBE\xAD\xDE\xBE\xBA\xFE\xCA') 
mu.reg_write(UC_X86_REG_GS_BASE, TEB_ADDR)

mu.mem_write(FUNC_ADDR, func_code)
mu.mem_write(SUB_ADDR, sub_code)

xor_key = b"somerandomkeydatazzzzzzzAMOTHERK@"
mu.mem_write(DATA_ADDR, xor_key)

mu.mem_write(INPUT_ADDR, b"Crazzyman1081\x00")
mu.mem_write(OUTPUT_ADDR, b"\x00" * 64)

rsp = STACK_BASE + STACK_SIZE - 0x1000
mu.reg_write(UC_X86_REG_RSP, rsp)
mu.reg_write(UC_X86_REG_RBP, rsp)

mu.reg_write(UC_X86_REG_RCX, INPUT_ADDR)   
mu.reg_write(UC_X86_REG_RDX, OUTPUT_ADDR)  

print(f"starting Emulation at {hex(FUNC_ADDR)}")

try:
    mu.emu_start(FUNC_ADDR, STOP_ADDR)
    print(" Emulation finished successfully.")
except UcError as e:
    print(f"EMU ERROR: {e}")
    rip = mu.reg_read(UC_X86_REG_RIP)
    print(f" RIP: {hex(rip)}")

out = mu.mem_read(OUTPUT_ADDR, 16)

vals = []
for i in range(0, 16, 4):
    v = int.from_bytes(out[i:i+4], "little")
    vals.append(v)
    print(f"[{i//4}] = 0x{v:08X}")

print("\n=== LICENSE KEY ===")
print(format_key(vals))
```