#!/usr/bin/env python
import random
import sys
from __builtin__ import bytearray

# Examples extracted from NIST Standard (https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf)

plainText = 123456789
bitlenght = 1024

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

def generateRandomOdd(bitlenght):
    x = random.getrandbits(bitlenght)
    if x % 2 == 0:
        return x+1
    return x

# Note this function is not deterministic, therefore it may fail. NIST assures with large random integers with more than 3 rounds is enough
# https://xlinux.nist.gov/dads/HTML/millerRabin.html
def probably_prime(n, k=10):
    if n == 2:
        return True
    if not n & 1:
        return False

    def check(a, s, d, n):
        x = pow(a, d, n)
        if x == 1:
            return True
        for i in xrange(s - 1):
            if x == n - 1:
                return True
            x = pow(x, 2, n)
        return x == n - 1

    s = 0
    d = n - 1

    while d % 2 == 0:
        d >>= 1
        s += 1

    for i in xrange(k):
        a = random.randrange(2, n - 1)
        if not check(a, s, d, n):
            return False
    return True

def gcd(a,b):
    while b != 0:
        a, b = b, a % b
    return a


def multiplicativeInverse(a, b):
    d = 0
    x1 = 0
    x2 = 1
    y1 = 1
    temp_b = b

    while a > 0:
        temp1 = temp_b / a
        temp2 = temp_b - temp1 * a
        temp_b = a
        a = temp2

        x = x2 - temp1 * x1
        y = d - temp1 * y1

        x2 = x1
        x1 = x
        d = y1
        y1 = y

    if temp_b == 1:
        return d + b

def keyGeneration():
    p = generateRandomOdd(bitlenght/2)
    while not probably_prime(p):
        p = p + 2
    q = generateRandomOdd(bitlenght/2)
    while not probably_prime(q):
        q = q + 2

    n = p*q

    t = (p-1)*(q-1)

    e = t-1

    while gcd(e,t) != 1:
        e -= 1

    d = multiplicativeInverse(e,t)

    return p, q, n, e, d

def l2r(m, e, n):
    # c = (m ^ e) % n
    A = 1
    for i in range(e.bit_length()):
        A = A * A
        if bin(e)[i] == str(1):
            A = A * m

        A = A % n

    return A

def r2l(m, e, n):
    # c = (m ^ e) % n
    A = 1
    for i in reversed(range(e.bit_length())):
        if bin(e)[i] == str(1):
            A = A * m
        m = m * m

        m = m % n
        A = A % n

    return A

def monLadder(m, e, n):
    A = m
    B = m*m

    B = B % n

    for i in range(1,e.bit_length()):
        if bin(e).lstrip('0b')[i] == str(1):
            A = A*B
            B = B*B

            A = A % n
            B = B % n
        if bin(e).lstrip('0b')[i] == str(0):
            B = A*B
            A = A*A

            A = A % n
            B = B % n

    return A

def monProduct(a, b, n):
    # Calculate n1 so that (r)(r^-1) - n*n1 = 1

    t = a * b
    m = t * n1 % r
    u = (t + m * n) / r
    if (u > n):
        u = u - n
    return u

def slidingWindows(m, e, n):
    return None

def kary(m, e, n):
    return None


### MAIN ###
args = sys.argv[1:]

if len(args) != 1:
    print "ERROR: 1 argument required"
    printUsage()
else:
    if str(args[0]) == "-h" or str(args[0]) == "--help":
        printUsage()
    if str(args[0]) == "l2r" or str(args[0]) == "r2l" or str(args[0]) == "slidingWindows" or str(args[0]) == "ladder" or str(args[0]) == "kary":
        print "Key Generation\n========="
        p, q, n, e, d = keyGeneration()
        print "p = " + str(p) + "\n"
        print "p has " + str(len(bin(p))) + " bits\n"
        print "q = " + str(q) + "\n"
        print "q has " + str(len(bin(q))) + " bits\n"
        print "n = " + str(n) + "\n"
        print "n has " + str(len(bin(n))) + " bits\n"
        print "e = " + str(e) + "\n"
        print "e has " + str(len(bin(e))) + " bits\n"
        print "d = " + str(d) + "\n"
        print "d has " + str(len(bin(d))) + " bits\n"

        print "Montgomery product\n========="
        a = 13
        b = 17
        n = 41

        print "Montgomery product of 13*17 mod 41 is " + str(monProduct(a, b, n)) + "\n"

        # cipheredText = (plainText ^ e) % n
        # decipheredText = (cipheredText ^ d) % n
        if str(args[0]) == "l2r":
            print "Left to Right\n========="
            cipheredText = l2r(plainText,e,n)
            print "Ciphered Text is " + str(cipheredText)

            decipheredText = l2r(cipheredText,d,n)
            print "Deciphered Text is " + str(decipheredText)

        elif str(args[0]) == "r2l":
            print "Right to Left\n========="
            cipheredText = r2l(plainText, e, n)
            print "Ciphered Text is " + str(cipheredText)

            decipheredText = r2l(cipheredText, d, n)
            print "Deciphered Text is " + str(decipheredText)
        elif str(args[0]) == "slidingWindows":
            print "Sliding Windows\n========="
            cipheredText = slidingWindows(plainText, e, n)
            print "Ciphered Text is " + str(cipheredText)

            decipheredText = slidingWindows(cipheredText, d, n)
            print "Deciphered Text is " + str(decipheredText)
        elif str(args[0]) == "ladder":
            print "Montgomery Ladder\n========="
            cipheredText = monLadder(plainText, e, n)
            print "Ciphered Text is " + str(cipheredText)

            decipheredText = monLadder(cipheredText, d, n)
            print "Deciphered Text is " + str(decipheredText)
        elif str(args[0]) == "kary":
            print "K-ary\n========="
            cipheredText = kary(plainText, e, n)
            print "Ciphered Text is " + str(cipheredText)

            decipheredText = kary(cipheredText, d, n)
            print "Deciphered Text is " + str(decipheredText)
    else:
        print "ERROR: First argument must be a valid exponentiation method or -h/--help"
        printUsage()
