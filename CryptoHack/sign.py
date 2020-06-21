#!/usr/bin/env python3

import os
import telnetlib
import json
import codecs
import base64
import binascii
from Crypto.Util.number import long_to_bytes, bytes_to_long

HOST = "socket.cryptohack.org"
PORT = 13374

tn = telnetlib.Telnet(HOST, PORT)


def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    tn.write(request)

MSG = 0
received = readline()
while True:  
    
    print("Received: ", received.decode())
    option = input("Your option: ")

    if(option == 'sign'):
        MSG = input("Your msg to sign: ")

    request = {
        "option": option, "msg": MSG
    }
    print("\n")
    json_send(request)
    received = readline()
    if(option == 'sign'):
        break

print(received.decode())
signed = input("Signed hex: ")
print(binascii.unhexlify(signed))
