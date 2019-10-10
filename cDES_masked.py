#!/usr/bin/env python
import sys
from __builtin__ import bytearray

# ASCII for 'abcdefgh'
plainText = [0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68]
expectedResult = [0xfc, 0x13, 0xbf, 0x72, 0x74, 0x90, 0x99, 0xac]

#maskX = [0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08]
maskX = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
maskX1L = ""
maskX1R = ""
maskX2 = ""

keyDES = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]
expectedExpandedKey = "000000000000000000000000000100000010001100000111000000000000000000000000001101000000000100000101000000000000000000000000000000100010000011000110000000000000000000000000011001001010000110000001000000000000000000000000001000100000010001001011000000000000000000000000010011101001000100000010000000000000000000000000000001000100010101101000000000000000000000000000010010001001100001000000000000000000000000000000010010001000000001111000000000000000000000000000100000011101110000001000000000000000000000000000000010000001011000110000000000000000000000000000100110010100100000100100000000000000000000000000000000000100101010010000000000000000000000000000100100010010000000010101000000000000000000000000101000110000001010000000000000000000000000000000000100110010001010000010"

s1 = [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
      [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
      [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
      [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]]

s2 = [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
      [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
      [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
      [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]]

s3 = [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
      [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
      [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
      [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]]

s4 = [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
      [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
      [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
      [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]]

s5 = [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
      [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
      [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
      [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]]

s6 = [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
      [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
      [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
      [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]]

s7 = [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
      [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
      [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
      [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]]

s8 = [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
      [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
      [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
      [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]

sM1 = [[None]*16, [None]*16, [None]*16, [None]*16]
sM2 = [[None]*16, [None]*16, [None]*16, [None]*16]
sM3 = [[None]*16, [None]*16, [None]*16, [None]*16]
sM4 = [[None]*16, [None]*16, [None]*16, [None]*16]
sM5 = [[None]*16, [None]*16, [None]*16, [None]*16]
sM6 = [[None]*16, [None]*16, [None]*16, [None]*16]
sM7 = [[None]*16, [None]*16, [None]*16, [None]*16]
sM8 = [[None]*16, [None]*16, [None]*16, [None]*16]

def printUsage():
    print("Usage: \n'python cDES.py [-h/--help]' to print this Usage\n'python cDES.py [N]' to cipher and decipher test plaintext")
    exit()


def initPermute(aux):
    # aux = bin(0).lstrip('0b')
    # for i in text:
    #     aux += bin(i).lstrip('0b').zfill(8)

    res= aux[57] + aux[49] + aux[41] + aux[33] + aux[25] + aux[17] + aux[9] + aux[
        1] + aux[59] + aux[51] + aux[43] + aux[35] + aux[27] + aux[19] + aux[11] + aux[
               3] + aux[61] + aux[53] + aux[45] + aux[37] + aux[29] + aux[21] + aux[13] + \
           aux[5] + aux[63] + aux[55] + aux[47] + aux[39] + aux[31] + aux[23] + aux[
               15] + aux[7] + aux[56] + aux[48] + aux[40] + aux[32] + aux[24] + aux[16] + \
           aux[8] + aux[0] + aux[58] + aux[50] + aux[42] + aux[34] + aux[26] + aux[
               18] + aux[10] + aux[2] + aux[60] + aux[52] + aux[44] + aux[36] + aux[28] + \
           aux[20] + aux[12] + aux[4] + aux[62] + aux[54] + aux[46] + aux[38] + aux[
               30] + aux[22] + aux[14] + aux[6]

    return res


def invInitPermute(aux):
    # aux = bin(0).lstrip('0b')
    # for i in text:
    #     aux += bin(i).lstrip('0b').zfill(8)

    res = aux[39] + aux[7] + aux[47] + aux[15] + aux[55] + aux[23] + aux[63] + aux[
        31] + aux[38] + aux[6] + aux[46] + aux[14] + aux[54] + aux[22] + aux[62] + aux[
                  30] + aux[37] + aux[5] + aux[45] + aux[13] + aux[53] + aux[21] + aux[61] + \
              aux[29] + aux[36] + aux[4] + aux[44] + aux[12] + aux[52] + aux[20] + aux[
                  60] + aux[28] + aux[35] + aux[3] + aux[43] + aux[11] + aux[51] + aux[19] + \
              aux[59] + aux[27] + aux[34] + aux[2] + aux[42] + aux[10] + aux[50] + aux[
                  18] + aux[58] + aux[26] + aux[33] + aux[1] + aux[41] + aux[9] + aux[49] + \
              aux[17] + aux[57] + aux[25] + aux[32] + aux[0] + aux[40] + aux[8] + aux[
                  48] + aux[16] + aux[56] + aux[24]

    return res

def sMBOX(chunk, s):
    if chunk[0] == "0" and chunk[5] == "0":
        i = 0
    elif chunk[0] == "0" and chunk[5] == "1":
        i = 1
    elif chunk[0] == "1" and chunk[5] == "0":
        i = 2
    elif chunk[0] == "1" and chunk[5] == "1":
        i = 3

    j = int(chunk[1:5],2)

    if s == 0:
        chunk = bin(sM1[i][j]).lstrip('0b').zfill(4)
    elif s == 1:
        chunk = bin(sM2[i][j]).lstrip('0b').zfill(4)
    elif s == 2:
        chunk = bin(sM3[i][j]).lstrip('0b').zfill(4)
    elif s == 3:
        chunk = bin(sM4[i][j]).lstrip('0b').zfill(4)
    elif s == 4:
        chunk = bin(sM5[i][j]).lstrip('0b').zfill(4)
    elif s == 5:
        chunk = bin(sM6[i][j]).lstrip('0b').zfill(4)
    elif s == 6:
        chunk = bin(sM7[i][j]).lstrip('0b').zfill(4)
    elif s == 7:
        chunk = bin(sM8[i][j]).lstrip('0b').zfill(4)
    else:
        print("Wrong s")
        exit()

    return chunk

def sBOX(chunk, s):
    if chunk[0] == "0" and chunk[5] == "0":
        i = 0
    elif chunk[0] == "0" and chunk[5] == "1":
        i = 1
    elif chunk[0] == "1" and chunk[5] == "0":
        i = 2
    elif chunk[0] == "1" and chunk[5] == "1":
        i = 3

    j = int(chunk[1:5], 2)

    if s == 0:
        chunk = bin(s1[i][j]).lstrip('0b').zfill(4)
    elif s == 1:
        chunk = bin(s2[i][j]).lstrip('0b').zfill(4)
    elif s == 2:
        chunk = bin(s3[i][j]).lstrip('0b').zfill(4)
    elif s == 3:
        chunk = bin(s4[i][j]).lstrip('0b').zfill(4)
    elif s == 4:
        chunk = bin(s5[i][j]).lstrip('0b').zfill(4)
    elif s == 5:
        chunk = bin(s6[i][j]).lstrip('0b').zfill(4)
    elif s == 6:
        chunk = bin(s7[i][j]).lstrip('0b').zfill(4)
    elif s == 7:
        chunk = bin(s8[i][j]).lstrip('0b').zfill(4)
    else:
        print("Wrong s")
        exit()

    return chunk


def eP(block):
    return block[31] + block[0] + block[1] + block[2] + block[3] + block[4] + block[3] + block[4] + block[5] + block[
        6] + block[7] + block[8] + block[7] + block[8] + block[9] + block[10] + block[11] + block[12] + block[11] + \
           block[12] + block[13] + block[14] + block[15] + block[16] + block[15] + block[16] + block[17] + block[18] + \
           block[19] + block[20] + block[19] + block[20] + block[21] + block[22] + block[23] + block[24] + block[23] + \
           block[24] + block[25] + block[26] + block[27] + block[28] + block[27] + block[28] + block[29] + block[30] + \
           block[31] + block[0]


# TODO: Fer servir les mascares
def feistelFunction(block, subKey):
    global maskX1L
    global maskX1R
    global maskX2
    # Expansion
    block = eP(block)
    print("Expansion: " + block)

    # Key Mixing
    input = bin(int(block, 2) ^ int(subKey, 2)).lstrip('0b').zfill(48)
    print("Key mixing: " + input)

    # Substitution
    res = ""
    for i in range(0, len(input), 6):
        res += sMBOX(input[i:i + 6], i / 6)
    print("sBox: " + res)

        # Permutation
    res = res[15] + res[6] + res[19] + res[20] + res[28] + res[11] + res[27] + res[16] + res[0] + res[14] + res[22] + \
          res[25] + res[4] + res[17] + res[30] + res[9] + res[1] + res[7] + res[23] + res[13] + res[31] + res[26] + res[
              2] + res[8] + res[18] + res[12] + res[29] + res[5] + res[21] + res[10] + res[3] + res[24]

    print("Permutation: " + res)

    return res


def cipher(key):
    global maskX1L
    global maskX1R
    global maskX2
    binText = bin(0).lstrip('0b')
    for i in plainText:
        binText += bin(i).lstrip('0b').zfill(8)
    binMask = bin(0).lstrip('0b')
    for i in maskX:
        binMask += bin(i).lstrip('0b').zfill(8)
    # print("Ciphering: Adding Mask\n=========")
    cipheredText = bin(int(binText, 2) ^ int(binMask, 2)).lstrip('0b').zfill(64)
    print("Ciphering: Initial Permutation\n=========")
    cipheredText = initPermute(cipheredText)

    maskX1 = initPermute(binMask)
    maskX1L = maskX1[:32]
    maskX1R = maskX1[32:]

    L = cipheredText[0:32]
    R = cipheredText[32:64]

    print("L: " + bin(int(L,2) ^ int(maskX1L,2)).lstrip('0b').zfill(32))
    print("R: " + bin(int(R,2) ^ int(maskX1R,2)).lstrip('0b').zfill(32))

    for r in range(15):
        print("Ciphering: Round " + str(r) + "\n=========")
        A = bin(int(R,2) ^ (int(maskX1L,2) ^ int(maskX1R,2))).lstrip('0b').zfill(32)
        R = bin(int(L, 2) ^ int(feistelFunction(R, key[48 * r:(48 * r) + 48]), 2)).lstrip('0b').zfill(32)
        L = A
        print("L: " + bin(int(L, 2) ^ int(maskX1L, 2)).lstrip('0b').zfill(32))
        print("R: " + bin(int(R, 2) ^ int(maskX1R, 2)).lstrip('0b').zfill(32))

    print("Ciphering: Last Round\n=========")
    L = bin(int(L, 2) ^ int(feistelFunction(R, key[-48:]), 2)).lstrip('0b').zfill(32)

    print("L: " + bin(int(L, 2) ^ int(maskX1L, 2)).lstrip('0b').zfill(32))
    print("R: " + bin(int(R, 2) ^ int(maskX1R, 2)).lstrip('0b').zfill(32))

    print("L: " + L)
    print("R: " + R)

    cipheredText = L + R

    cipheredText = invInitPermute(cipheredText)

    cipheredText = bin(int(cipheredText, 2) ^ int(binMask, 2)).lstrip('0b').zfill(64)

    return cipheredText


def decipher(key):
    global maskX1L
    global maskX1R
    global maskX2
    binText = bin(0).lstrip('0b')
    for i in expectedResult:
        binText += bin(i).lstrip('0b').zfill(8)
    binMask = bin(0).lstrip('0b')
    for i in maskX:
        binMask += bin(i).lstrip('0b').zfill(8)
    print("Deciphering: Adding Mask\n=========")
    decipheredText = bin(int(binText, 2) ^ int(binMask, 2)).lstrip('0b').zfill(64)
    print("Deciphering: Initial Permutation\n=========")
    decipheredText = initPermute(cipheredText)

    maskXIP = initPermute(binMask)
    maskX1L = maskXIP[:32]
    maskX1R = maskXIP[32:]

    L = decipheredText[0:32]
    R = decipheredText[32:64]

    print("L: " + L)
    print("R: " + R)

    for r in range(15):
        print("Deciphering: Round " + str(r) + "\n=========")
        A = A = bin(int(R,2) ^ (int(maskX1L,2) ^ int(maskX1R,2))).lstrip('0b').zfill(32)
        R = bin(int(L, 2) ^ int(feistelFunction(R, key[768 - (48 * r) - 48:768 - (48 * r)]), 2)).lstrip('0b').zfill(32)
        L = A

        print("L: " + L)
        print("R: " + R)

    print("Deciphering: Last Round\n=========")
    L = bin(int(L, 2) ^ int(feistelFunction(R, key[:48]), 2)).lstrip('0b').zfill(32)

    print("L: " + L)
    print("R: " + R)

    decipheredText = L + R

    decipheredText = invInitPermute(decipheredText)

    decipheredText = bin(int(decipheredText, 2) ^ int(binMask, 2)).lstrip('0b').zfill(64)

    return decipheredText


def keyExpansion():
    keyBits = bin(0).lstrip('0b')
    for i in keyDES:
        keyBits += bin(i).lstrip('0b').zfill(8)

    # PC 1
    keyBits = keyBits[56] + keyBits[48] + keyBits[40] + keyBits[32] + keyBits[24] + keyBits[16] + keyBits[8] + keyBits[
        0] + keyBits[57] + keyBits[49] + keyBits[41] + keyBits[33] + keyBits[25] + keyBits[17] + keyBits[9] + keyBits[
                  1] + keyBits[58] + keyBits[50] + keyBits[42] + keyBits[34] + keyBits[26] + keyBits[18] + keyBits[
                  10] + keyBits[2] + keyBits[59] + keyBits[51] + keyBits[43] + keyBits[35] + keyBits[62] + keyBits[
                  54] + keyBits[46] + keyBits[38] + keyBits[30] + keyBits[22] + keyBits[14] + keyBits[6] + keyBits[
                  61] + keyBits[53] + keyBits[45] + keyBits[37] + keyBits[29] + keyBits[21] + keyBits[13] + keyBits[
                  5] + keyBits[60] + keyBits[52] + keyBits[44] + keyBits[36] + keyBits[28] + keyBits[20] + keyBits[
                  12] + keyBits[4] + keyBits[27] + keyBits[19] + keyBits[11] + keyBits[3]

    # print(keyBits)

    LK = keyBits[0:28]
    RK = keyBits[28:56]

    subKeyBits = []

    for i in range(16):
        if i == 0 or i == 1 or i == 8 or i == 15:
            LK = ((int(LK, 2) << 1) & 0xFFFFFFF) | ((int(LK, 2) >> 27) * 0x01)
            RK = ((int(RK, 2) << 1) & 0xFFFFFFF) | ((int(RK, 2) >> 27) * 0x01)
        else:
            LK = ((int(LK, 2) << 1) & 0xFFFFFFF) | ((int(LK, 2) >> 27) * 0x01)
            RK = ((int(RK, 2) << 1) & 0xFFFFFFF) | ((int(RK, 2) >> 27) * 0x01)
            LK = bin(LK).lstrip('0b').zfill(28)
            RK = bin(RK).lstrip('0b').zfill(28)
            LK = ((int(LK, 2) << 1) & 0xFFFFFFF) | ((int(LK, 2) >> 27) * 0x01)
            RK = ((int(RK, 2) << 1) & 0xFFFFFFF) | ((int(RK, 2) >> 27) * 0x01)
        LK = bin(LK).lstrip('0b').zfill(28)
        RK = bin(RK).lstrip('0b').zfill(28)
        subKeyBits.append(LK + RK)

    keyBits = ""
    for sK in subKeyBits:
        # PC 2
        keyBits += sK[13] + sK[16] + sK[10] + sK[23] + sK[0] + sK[4] + sK[2] + sK[27] + sK[14] + sK[5] + sK[20] + sK[
            9] + sK[22] + sK[18] + sK[11] + sK[3] + sK[25] + sK[7] + sK[15] + sK[6] + sK[26] + sK[19] + sK[12] + sK[
                       1] + sK[40] + sK[51] + sK[30] + sK[36] + sK[46] + sK[54] + sK[29] + sK[39] + sK[50] + sK[44] + \
                   sK[32] + sK[47] + sK[43] + sK[48] + sK[38] + sK[55] + sK[33] + sK[52] + sK[45] + sK[41] + sK[49] + \
                   sK[35] + sK[28] + sK[31]

    return keyBits

def calculateSMBox():
    global sM1
    global sM2
    global sM3
    global sM4
    global sM5
    global sM6
    global sM7
    global sM8

    binMask = bin(0).lstrip('0b')
    for i in maskX:
        binMask += bin(i).lstrip('0b').zfill(8)

    maskXIP = initPermute(binMask)
    maskX1L = maskXIP[:32]
    maskX1R = maskXIP[32:]
    maskX2 = eP(maskX1R)

    invPermutationMask = bin(int(maskX1L,2) ^ int(maskX1R,2)).lstrip('0b').zfill(32)
    invPermutationMask = invPermutationMask[8] + invPermutationMask[16] + invPermutationMask[22] + invPermutationMask[
        30] + invPermutationMask[12] + invPermutationMask[27] + invPermutationMask[1] + invPermutationMask[17] + \
                         invPermutationMask[23] + invPermutationMask[15] + invPermutationMask[29] + invPermutationMask[
                             5] + invPermutationMask[25] + invPermutationMask[19] + invPermutationMask[9] + \
                         invPermutationMask[0] + invPermutationMask[7] + invPermutationMask[13] + invPermutationMask[
                             24] + invPermutationMask[2] + invPermutationMask[3] + invPermutationMask[28] + \
                         invPermutationMask[10] + invPermutationMask[18] + invPermutationMask[31] + invPermutationMask[
                             11] + invPermutationMask[21] + invPermutationMask[6] + invPermutationMask[4] + \
                         invPermutationMask[26] + invPermutationMask[14] + invPermutationMask[20]

    res = ""
    res1 = ""
    res2 = ""
    res3 = ""
    res4 = ""
    res5 = ""
    res6 = ""
    res7 = ""
    for a in range(64):
        input = bin(a).lstrip('0b').zfill(6)

        input0 = bin(int(input,2) ^ int(maskX2[0:6],2)).lstrip('0b').zfill(6)
        input1 = bin(int(input,2) ^ int(maskX2[6:12],2)).lstrip('0b').zfill(6)
        input2 = bin(int(input,2) ^ int(maskX2[12:18],2)).lstrip('0b').zfill(6)
        input3 = bin(int(input,2) ^ int(maskX2[18:24],2)).lstrip('0b').zfill(6)
        input4 = bin(int(input,2) ^ int(maskX2[24:30],2)).lstrip('0b').zfill(6)
        input5 = bin(int(input,2) ^ int(maskX2[30:36],2)).lstrip('0b').zfill(6)
        input6 = bin(int(input,2) ^ int(maskX2[36:42],2)).lstrip('0b').zfill(6)
        input7 = bin(int(input,2) ^ int(maskX2[42:48],2)).lstrip('0b').zfill(6)

        res = sBOX(input0, 0)
        res1 = sBOX(input1, 1)
        res2 = sBOX(input2, 2)
        res3 = sBOX(input3, 3)
        res4 = sBOX(input4, 4)
        res5 = sBOX(input5, 5)
        res6 = sBOX(input6, 6)
        res7 = sBOX(input7, 7)

        res = bin(int(res, 2) ^ int(invPermutationMask[0:4], 2)).lstrip('0b').zfill(32)
        res1 = bin(int(res1, 2) ^ int(invPermutationMask[4:8], 2)).lstrip('0b').zfill(32)
        res2 = bin(int(res2, 2) ^ int(invPermutationMask[8:12], 2)).lstrip('0b').zfill(32)
        res3 = bin(int(res3, 2) ^ int(invPermutationMask[12:16], 2)).lstrip('0b').zfill(32)
        res4 = bin(int(res4, 2) ^ int(invPermutationMask[16:20], 2)).lstrip('0b').zfill(32)
        res5 = bin(int(res5, 2) ^ int(invPermutationMask[20:24], 2)).lstrip('0b').zfill(32)
        res6 = bin(int(res6, 2) ^ int(invPermutationMask[24:28], 2)).lstrip('0b').zfill(32)
        res7 = bin(int(res7, 2) ^ int(invPermutationMask[28:32], 2)).lstrip('0b').zfill(32)

        if input[0] == "0" and input[5] == "0":
            i = 0
        elif input[0] == "0" and input[5] == "1":
            i = 1
        elif input[0] == "1" and input[5] == "0":
            i = 2
        elif input[0] == "1" and input[5] == "1":
            i = 3

        j = int(input[1:5], 2)

        sM1[i][j] = int(res,2)
        sM2[i][j] = int(res1,2)
        sM3[i][j] = int(res2,2)
        sM4[i][j] = int(res3,2)
        sM5[i][j] = int(res4,2)
        sM6[i][j] = int(res5,2)
        sM7[i][j] = int(res6,2)
        sM8[i][j] = int(res7,2)


### MAIN ###
args = sys.argv[1:]

if len(args) != 1:
    print("ERROR: 1 argument required")
    printUsage()
else:
    if str(args[0]) == "-h" or str(args[0]) == "--help":
        printUsage()
    elif str(args[0]) == "N":
        print("Arguments correctly provided")
        keyExpanded = keyExpansion()
        if (keyExpanded == expectedExpandedKey):
            print("KeyExpansion correcta")
        else:
            print("KeyExpansion incorrecta")

        calculateSMBox()

        # print("sM1: " + str(sM1))
        # print("sM2: " + str(sM2))
        # print("sM3: " + str(sM3))
        # print("sM4: " + str(sM4))
        # print("sM5: " + str(sM5))
        # print("sM6: " + str(sM6))
        # print("sM7: " + str(sM7))
        # print("sM8: " + str(sM8))

        cipheredText = cipher(keyExpanded)
        hexCipheredText = []
        for i in range(0, len(cipheredText), 8):
            hexCipheredText.append(hex(int(cipheredText[i:i + 8], 2)).rstrip('L'))

        print("Ciphered Text is: ")
        print(str(hexCipheredText))

        decipheredText = decipher(keyExpanded)
        hexDecipheredText = []
        for i in range(0, len(decipheredText), 8):
            hexDecipheredText.append(hex(int(decipheredText[i:i + 8], 2)).rstrip('L'))

        print("Deciphered Text is: ")
        print(str(hexDecipheredText))
    else:
        print("ERROR: First argument must be a valid type or -h/--help")
        printUsage()
