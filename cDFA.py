#!/usr/bin/env python
import os
import sys

affectedColumn1 = [1,0,0,0,0,0,0,1,0,0,1,0,0,1,0,0]
affectedColumn2 = [0,1,0,0,1,0,0,0,0,0,0,1,0,0,1,0]
affectedColumn3 = [0,0,1,0,0,1,0,0,1,0,0,0,0,0,0,1]
affectedColumn4 = [0,0,0,1,0,0,1,0,0,1,0,0,1,0,0,0]

sBox = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82,
        0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
        0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96,
        0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
        0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
        0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
        0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff,
        0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32,
        0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
        0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
        0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
        0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e,
        0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
        0xb0, 0x54, 0xbb, 0x16]


def printUsage():
    print("Usage: \n'python cDFA.py [-h/--help]' to print this Usage\n'python cDFA.py [128/192/256] outputFile' to attack the output with DFA assuming an AES 128/192/256 respectively")
    exit()

def xor(x, y):
    res = []
    for i in range(4):
        for j in range(4):
            res.append(x[4 * i + j] ^ y[4 * i + j])

    return res

def gfDegree(a):
    res = 0
    a >>= 1
    while (a != 0):
        a >>= 1;
        res += 1;
    return res


def multiply(v, G):
    result = []
    for i in range(len(G[0])):  # this loops through columns of the matrix
        total = 0
        for j in range(len(v)):  # this loops through vector coordinates & rows of matrix
            total ^= int(v[j]) & int(G[j][i])
        result.append(total)
    return result

def subBytes(byte):
    return sBox[byte]

def shiftRows(block):
    print("Shift Rows\n=========")
    return [[block[0][0], block[1][0], block[2][0], block[3][0]],
            [block[1][1], block[2][1], block[3][1], block[0][1]],
            [block[2][2], block[3][2], block[0][2], block[1][2]],
            [block[3][3], block[0][3], block[1][3], block[2][3]]]

def isModified(bit):
    return int(bit/bit) if bit else 0

def checkFault(error):
    masked = [isModified(e) for e in error]
    if masked == affectedColumn1:
        return 1
    elif masked == affectedColumn2:
        return 2
    elif masked == affectedColumn3:
        return 3
    elif masked == affectedColumn4:
        return 4
    else:
        return -1

def determineSubKey(b, correct):
    SBb = []
    print("Matrix of chosen values")
    aux = []
    aux.append(subBytes(b[0]))
    aux.append(subBytes(b[4]))
    aux.append(subBytes(b[8]))
    aux.append(subBytes(b[12]))
    SBb.append(aux)
    print(str(aux))
    aux = []
    aux.append(subBytes(b[1]))
    aux.append(subBytes(b[5]))
    aux.append(subBytes(b[9]))
    aux.append(subBytes(b[13]))
    SBb.append(aux)
    print(str(aux))
    aux = []
    aux.append(subBytes(b[2]))
    aux.append(subBytes(b[6]))
    aux.append(subBytes(b[10]))
    aux.append(subBytes(b[14]))
    SBb.append(aux)
    print(str(aux))
    aux = []
    aux.append(subBytes(b[3]))
    aux.append(subBytes(b[7]))
    aux.append(subBytes(b[11]))
    aux.append(subBytes(b[15]))
    SBb.append(aux)
    print(str(aux))

    
    aux = shiftRows(SBb)
    shiftedB = []
    for i in range(4):
        for j in range(4):
            shiftedB.append(aux[i][j])

    k = []

    k.append(shiftedB[0] ^ correct[0])
    k.append(shiftedB[4] ^ correct[1])
    k.append(shiftedB[8] ^ correct[2])
    k.append(shiftedB[12] ^ correct[3])

    k.append(shiftedB[7] ^ correct[4])
    k.append(shiftedB[11] ^ correct[5])
    k.append(shiftedB[15] ^ correct[6])
    k.append(shiftedB[3] ^ correct[7])

    k.append(shiftedB[10] ^ correct[8])
    k.append(shiftedB[14] ^ correct[9])
    k.append(shiftedB[2] ^ correct[10])
    k.append(shiftedB[6] ^ correct[11])

    k.append(shiftedB[13] ^ correct[12])
    k.append(shiftedB[1] ^ correct[13])
    k.append(shiftedB[5] ^ correct[14])
    k.append(shiftedB[9] ^ correct[15])
    return k

def SL(B):
    return 0xFF&((B<<1)^((B>>7)*(0x1B)))

def multiplyGalois(a,b):
    X=0
    Y=b
    while a!=0:
        if a&1:
            X=X^Y
        Y=SL(Y)
        a=a>>1
    return X

def findCandidates(column):
    candidates = []
    if checkFault(column[0]) == 1:
        for eout in column:
            for ein in range(256):
                doubleEin = multiplyGalois(2,ein)
                tripleEin = multiplyGalois(3,ein)
                #print("Ein: " + str(ein))
                for b1 in range(256):
                    #print("B1: " + str(b1))
                    if subBytes(b1 ^ doubleEin) == (subBytes(b1) ^ eout[0]):
                        for b2 in range(256):
                            #print("B2: " + str(b2))
                            if subBytes(b2 ^ ein) == (subBytes(b2) ^ eout[13]):
                                for b3 in range(256):
                                    #print("B3: " + str(b3))
                                    if subBytes(b3 ^ ein) == (subBytes(b3) ^ eout[10]):
                                        for b4 in range(256):
                                            #print("B4: " + str(b4))
                                            if subBytes(b4 ^ tripleEin) == (subBytes(b4) ^ eout[7]):
                                                candidates.append([b1,b2,b3,b4])
        print("Candidates: " + str(candidates))
        return candidates
    elif checkFault(column[0]) == 2:
        for eout in column:
            for ein in range(256):
                doubleEin = multiplyGalois(2,ein)
                tripleEin = multiplyGalois(3,ein)
                #print("Ein: " + str(ein))
                for b1 in range(256):
                    #print("B1: " + str(b1))
                    if subBytes(b1 ^ tripleEin) == (subBytes(b1) ^ eout[4]):
                        for b2 in range(256):
                            #print("B2: " + str(b2))
                            if subBytes(b2 ^ doubleEin) == (subBytes(b2) ^ eout[1]):
                                for b3 in range(256):
                                    #print("B3: " + str(b3))
                                    if subBytes(b3 ^ ein) == (subBytes(b3) ^ eout[14]):
                                        for b4 in range(256):
                                            #print("B4: " + str(b4))
                                            if subBytes(b4 ^ ein) == (subBytes(b4) ^ eout[11]):
                                                candidates.append([b1,b2,b3,b4])
        print("Candidates: " + str(candidates))
        return candidates
    elif checkFault(column[0]) == 3:
        for eout in column:
            for ein in range(256):
                doubleEin = multiplyGalois(2,ein)
                tripleEin = multiplyGalois(3,ein)
                #print("Ein: " + str(ein))
                for b1 in range(256):
                    #print("B1: " + str(b1))
                    if subBytes(b1 ^ ein) == (subBytes(b1) ^ eout[8]):
                        for b2 in range(256):
                            #print("B2: " + str(b2))
                            if subBytes(b2 ^ tripleEin) == (subBytes(b2) ^ eout[5]):
                                for b3 in range(256):
                                    #print("B3: " + str(b3))
                                    if subBytes(b3 ^ doubleEin) == (subBytes(b3) ^ eout[2]):
                                        for b4 in range(256):
                                            #print("B4: " + str(b4))
                                            if subBytes(b4 ^ ein) == (subBytes(b4) ^ eout[15]):
                                                candidates.append([b1,b2,b3,b4])
        print("Candidates: " + str(candidates))
        return candidates
    elif checkFault(column[0]) == 4:
        for eout in column:
            for ein in range(256):
                doubleEin = multiplyGalois(2,ein)
                tripleEin = multiplyGalois(3,ein)
                #print("Ein: " + str(ein))
                for b1 in range(256):

                    #print("B1: " + str(b1))
                    if subBytes(b1 ^ ein) == (subBytes(b1) ^ eout[12]):
                        for b2 in range(256):
                            #print("B2: " + str(b2))
                            if subBytes(b2 ^ ein) == (subBytes(b2) ^ eout[9]):
                                for b3 in range(256):
                                    #print("B3: " + str(b3))
                                    if subBytes(b3 ^ tripleEin) == (subBytes(b3) ^ eout[6]):
                                        for b4 in range(256):
                                            #print("B4: " + str(b4))
                                            if subBytes(b4 ^ doubleEin) == (subBytes(b4) ^ eout[3]):
                                                candidates.append([b1,b2,b3,b4])
        print("Candidates: " + str(candidates))
        return candidates

def chooseValues(candidates):
    cur_length = 0
    max_length = 0
    cur_i = 0
    max_i = 0
    cur_item = None
    max_item = None
    total_max_lenght = 0
    for i, item in sorted(enumerate(candidates), key=lambda x: x[1]):
        if cur_item is None or cur_item != item:
            if cur_length > max_length or (cur_length == max_length and cur_i < max_i):
                max_length = cur_length
                max_i = cur_i
                max_item = cur_item
                total_max_lenght = max_length
            cur_length = 1
            cur_i = i
            cur_item = item
        else:
            cur_length += 1
    if cur_length > max_length or (cur_length == max_length and cur_i < max_i):
        return cur_item
    print("Most repeated array is: " + str(max_item) + " with " + str(total_max_lenght) + " repetitions.")
    return max_item

def rotate(byte):
    a = byte[0]
    for i in range(3):
        byte[i] = byte[i + 1]
    byte[3] = a
    return byte


def rcon(byte):
    c = 1
    if byte == 0:
        return 0
    while byte != 1:
        b = c & 0x80
        c = (c * 2) & 0xFF
        if b == 0x80:
            c ^= 0x1B
        byte -= 1
    return c

def invKeyExpansion(key, keyLength):
    if keyLength == 128:
        resultKey = [0] * 176
        # White
        for a in range(16):
            resultKey[160+a] = key[a]
        for b in resultKey:
            print(str(hex(b)))
        c = 159
        i = 10
        t = [None] * 4
        while (c > 0):
            # Green
            # Save W[i-1] in t
            for a in range(4):
                t[a] = resultKey[c + 12 - a]
            # If its a green spot
            if (((c-3) % 16) == 0):
                # rotate w[i-1]
                t = list(reversed(t))
                rotate(t)
                t = list(reversed(t))
                # And SubBytes w[i-1]
                for a in range(4):
                    t[a] = subBytes(t[a])
                # And xor it with rcon[i/Nk]
                t[3] ^= rcon(i)
                i -= 1
            # Even if its red or green, you have to xor it with W[i-Nk]
            for a in range(4):
                resultKey[c] = (resultKey[c + 16] ^ t[a])
                c -= 1
        return resultKey
    if keyLength == 192:
        resultKey = [0] * 208
        # White
        resultKey += key
        c = 191
        i = 12
        t = [None] * 4
        while (c > 0):
            # Green
            for a in range(4):
                t[a] = resultKey[c + 20 - a]
            if (((c-3) % 24) == 0):
                t = list(reversed(t))
                rotate(t)
                t = list(reversed(t))
                for a in range(4):
                    t[a] = subBytes(t[a])
                t[3] ^= rcon(i)
                i -= 1
            # Red
            for a in range(4):
                resultKey.append(resultKey[c + 24] ^ t[a])
                c += 1
        return resultKey
    if keyLength == 256:
        resultKey = [0] * 240
        # White
        resultKey += key
        c = 223
        i = 14
        t = [None] * 4
        while (c > 0):
            # Green
            for a in range(4):
                t[a] = resultKey[c + 28 - a]
            if (((c-3) % 32) == 0):
                t = list(reversed(t))
                rotate(t)
                t = list(reversed(t))
                for a in range(4):
                    t[a] = subBytes(t[a])
                t[3] ^= rcon(i)
                i -= 1
            # Black
            elif (((c-3) % 32) == 16):
                for a in range(4):
                    t[a] = subBytes(t[a])
            # Red
            for a in range(4):
                resultKey.append(resultKey[c + 32] ^ t[a])
                c += 1
        return resultKey

### MAIN ###
args = sys.argv[1:]

if len(args) < 1 or len(args) > 2:
    print("ERROR: 2 arguments required, or -h/--help")
    printUsage()
else:
    if str(args[0]) == "-h" or str(args[0]) == "--help":
        printUsage()
    elif len(args) == 2:
        keyLength = int(args[0])
        path = str(args[1])
        if 128 != keyLength and 192 != keyLength and 256 != keyLength:
            print("ERROR: First argument must be a valid keyLength or -h/--help")
            printUsage()
        else:
            if not os.path.isfile(path):
                print("ERROR: Second argument must be a valid path to the output data file")
                printUsage()
            else:
                print("Arguments correctly provided")
                # Getting lines from output
                output = []
                with open(path, 'r') as file:
                    for line in file:
                        output.append(line)
                # Separating correct from faults
                correct = output[0]
                faults = output[1:]
                # Making it arrays and then converting elements from str to int
                correct = correct.replace("\n","").split(",")
                for i, f in enumerate(faults):
                    faults[i] = f.replace("\n","").split(",")
                    for j in range(16):
                        faults[i][j] = int(faults[i][j], 16)
                for i in range(16):
                    correct[i] = int(correct[i],16)

                '''
                print("Output to analyze is:")
                for c in correct:
                    print("Correct: " + str(hex(c)))
                for index, value in enumerate(faults):
                    for v in value:
                        print("Fault " + str(index+1) + ": " + str(hex(v)))
                '''
                errors = []
                for fault in faults:
                    print("Checking " + str(correct) + " against " + str(fault))
                    res = xor(correct, fault)
                    print("Result: " + str(res))
                    errors.append(res)
                if keyLength == 128:
                    print("128 chosen")
                    column1 = []
                    column2 = []
                    column3 = []
                    column4 = []
                    for i,e in enumerate(errors):
                        if checkFault(e) == 1:
                            print("Fault " + str(i+1) + " is valid for column 1")
                            column1.append(e)
                        elif checkFault(e) == 2:
                            print("Fault " + str(i+1) + " is valid for column 2")
                            column2.append(e)
                        elif checkFault(e) == 3:
                            print("Fault " + str(i+1) + " is valid for column 3")
                            column3.append(e)
                        elif checkFault(e) == 4:
                            print("Fault " + str(i+1) + " is valid for column 4")
                            column4.append(e)
                    print("Total valid faults: " + str(len(column1)+len(column2)+len(column3)+len(column4)))
                    possibleValues1 = findCandidates(column1)
                    possibleValues2 = findCandidates(column2)
                    possibleValues3 = findCandidates(column3)
                    possibleValues4 = findCandidates(column4)
                    print("Column 1")
                    chosenValues = chooseValues(possibleValues1)
                    print("Column 2")
                    chosenValues += chooseValues(possibleValues2)
                    print("Column 3")
                    chosenValues += chooseValues(possibleValues3)
                    print("Column 4")
                    chosenValues += chooseValues(possibleValues4)

                    subkey = determineSubKey(chosenValues,correct)

                    print("Subkey10 is:")
                    for b in subkey:
                        print(str(hex(b)))

                    key = invKeyExpansion(subkey, keyLength)

                    print("Key is:")
                    for b in key[0:16]:
                        print(str(hex(b)))

                elif keyLength == 192:
                    print("192 chosen but not supported yet")
                elif keyLength == 256:
                    print("256 chosen but not supported yet")
    else:
        printUsage()
