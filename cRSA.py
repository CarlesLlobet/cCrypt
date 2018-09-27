#!/usr/bin/env python
import sys
from __builtin__ import bytearray

# Examples extracted from NIST Standard (https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf)

plainText = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]

def printUsage():
    print "Usage: \n'python cRSA.py [-h/--help]' to print this Usage\n'python cRSA.py [l2r/r2l/slidingWindows/ladder]' to cipher and decipher test plaintext"
    exit()

def listToMatrix(byte):
    block = []
    for i in range(4):
        row = [None] * 4
        for j in range(4):
            row[j] = byte[i * 4 + j]
        block.append(row)
    return block

def keyGeneration():
    key = []
    return key

def cipher(e,n):
    print "Ciphering\n========="
    cipheredText = listToMatrix(plainText)
    cipheredText = (cipheredText^e) % n
    return cipheredText

def decipher(cipheredText,d,n):
    print "Deciphering\n========="
    decipheredText = (cipheredText^d) % n
    return decipheredText

### MAIN ###
args = sys.argv[1:]

if len(args) != 1:
    print "ERROR: 1 argument required"
    printUsage()
else:
    if str(args[0]) == "-h" or str(args[0]) == "--help":
        printUsage()
    elif str(args[0]) == "l2r":
        keyGeneration()
        cipher()
    elif str(args[0]) == "r2l":
        keyGeneration()
        cipher()
    elif str(args[0]) == "slidingWindows":
        keyGeneration()
        cipher()
    elif str(args[0]) == "ladder":
        keyGeneration()
        cipher()
    else:
        print "ERROR: First argument must be a valid exponentiation method or -h/--help"
        printUsage()
