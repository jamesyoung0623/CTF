#!/usr/bin/env python3

import telnetlib
import json
import codecs
import base64
from Crypto.Util.number import long_to_bytes, bytes_to_long

HOST = "socket.cryptohack.org"
PORT = 13377

tn = telnetlib.Telnet(HOST, PORT)


def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    tn.write(request)

def decoder(typ, text):
    if typ == 'base64':
        return base64.standard_b64decode(text).decode('ascii')
    elif typ == 'hex':
        return bytes.fromhex(text).decode('ascii')
    elif typ == 'bigint':
        t = int(text, 16)
        return long_to_bytes(t).decode('ascii')
    elif typ == 'utf-8':
        r = ""
        for x in text:
            r += chr(x)
        return r
    elif typ == 'rot13':
        return codecs.decode(text, 'rot_13')
            
    return text


received = json_recv()
while received.__contains__('error') == False and received.__contains__('flag') == False:  
    
    request = {
        "decoded": decoder(received["type"], received["encoded"])
    }
    
    print("Received type: ", received["type"])
    print("Received encoded value: ", received["encoded"])  
    print("Return: ", request["decoded"])
    print("\n")
    json_send(request)
    received = json_recv()

print(received)