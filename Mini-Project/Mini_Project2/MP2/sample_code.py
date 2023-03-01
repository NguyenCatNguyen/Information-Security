#!/usr/bin/python3

# XOR two bytearrays
def xor(first, second):
   return bytearray(x^y for x,y in zip(first, second))

MSG   = "This is a known message!"
HEX_1 = "a469b1c502c1cab966965e50425438e1bb1b5f9037a4c159"
HEX_2 = "bf73bcd3509299d566c35b5d450337e1bb175f903fafc15"

# Convert ascii string to bytearray
msg = bytearray(MSG, 'utf-8')

# Convert hex string to bytearray
hex1 = bytearray.fromhex(HEX_1)
hex2 = bytearray.fromhex(HEX_2)

C1 = bytearray.fromhex("a469b1c502c1cab966965e50425438e1bb1b5f9037a4c159")
C2 = bytearray.fromhex("bf73bcd3509299d566c35b5d450337e1bb175f903fafc159")
P2 = xor(C2, C1)
print(P2.decode('utf-8'))
