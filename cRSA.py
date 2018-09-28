#!/usr/bin/env python
import random
import sys
from __builtin__ import bytearray

# Examples extracted from NIST Standard (https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf)

plainText = 123456789
bitlenght = 1024

counterSqrts = 0
counterProducts = 0

def printUsage():
    print "Usage: \n'python cRSA.py [-h/--help]' to print this Usage\n'python cRSA.py [l2r/r2l/slidingWindow/ladder/kary]' to cipher and decipher test plaintext"
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
    global counterSqrts
    global counterProducts

    A = 1
    for i in range(e.bit_length()):
        A = A * A
        counterSqrts += 1
        if bin(e)[i] == str(1):
            A = A * m
            counterProducts += 1

        A = A % n

    return A

def r2l(m, e, n):
    # c = (m ^ e) % n
    global counterSqrts
    global counterProducts

    A = 1
    for i in reversed(range(e.bit_length())):
        if bin(e)[i] == str(1):
            A = A * m
            counterProducts += 1
        m = m * m
        counterSqrts += 1

        m = m % n
        A = A % n

    return A

def monLadder(m, e, n):
    global counterSqrts
    global counterProducts

    A = m
    B = m*m
    counterSqrts += 1

    B = B % n

    for i in range(1,e.bit_length()):
        if bin(e).lstrip('0b')[i] == str(1):
            A = A*B
            counterProducts += 1
            B = B*B
            counterSqrts += 1

            A = A % n
            B = B % n
        if bin(e).lstrip('0b')[i] == str(0):
            B = A*B
            counterProducts += 1
            A = A*A
            counterSqrts += 1

            A = A % n
            B = B % n

    return A

def findBezoutCoef(a, b):
    """
        Returns a list `result` of size 3 where:
        Referring to the equation ax + by = gcd(a, b)
            result[0] is gcd(a, b)
            result[1] is x
            result[2] is y
        """
    s = 0;
    old_s = 1
    t = 1;
    old_t = 0
    r = b;
    old_r = a

    while r != 0:
        quotient = old_r / r
        # This is a pythonic way to swap numbers
        # See the same part in C++ implementation below to know more
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    return [old_r, old_s, old_t]

def monProduct(a, b, n):
    # Calculate n1 so that (r)(r^-1) - n*n1 = 1
    # r = 2^k where 2^k-1 < n < 2^k
    r = 2
    while r < n:
        r = r * 2
    gcd, r1, n1 = findBezoutCoef(r,n)

    n1 = -n1

    t = a * b
    m = t * n1 % r
    u = (t + m * n) / r
    if (u > n):
        u = u - n
    return u

def kary(m, e, n, k=3):
    global counterSqrts
    global counterProducts

    j = 2 ** k
    #Afegim 0 al final si no te el # de grups bo
    g = bin(e).lstrip('0b')
    while (len(g) % k) != 0:
        g = g.zfill(len(g)+1)

    g2 = []
    for i in range(0, len(g), k):
        aux = ""
        for y in range(k):
            aux += str(g[i+y])
        g2.append(m**int(aux,2))

    A = g2[0]
    for i in range(1, len(g2)):
        A = (A**j) * (g2[i])
        counterProducts += 1
        A = A % n

    return A

def slidingWindow(m, e, n, k=3):
    global counterSqrts
    global counterProducts

    j = 2 ** k

    if e == 0:
        g = "0"
    else:
        g = bin(e).lstrip('0b')

    i = len(g)-1
    g2 = []
    while i > -1:
        if str(g[i]) == str(0):
            g2.append(int(0))
            i -= 1
        else:
            aux = ""
            for y in range(k):
                if i-y > -1:
                    aux += str(g[i - y])
            i -= k
            g2.append(m ** int(aux[::-1], 2) % n)

    g2 = list(reversed(g2))
    A = g2[0]
    for i in range(1, len(g2)):
        if g2[i] == 0:
            A = A*A
            counterSqrts += 1
            A = A % n
        else:
            A = (A ** j) * (g2[i])
            counterProducts += 1
            A = A % n
    if A == 0: return 1
    return A

### MAIN ###
args = sys.argv[1:]

if len(args) != 1:
    print "ERROR: 1 argument required"
    printUsage()
else:
    if str(args[0]) == "-h" or str(args[0]) == "--help":
        printUsage()
    if str(args[0]) == "l2r" or str(args[0]) == "r2l" or str(args[0]) == "slidingWindow" or str(args[0]) == "ladder" or str(args[0]) == "kary":
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

        # cipheredText = (plainText ^ e) % n
        # decipheredText = (cipheredText ^ d) % n
        if str(args[0]) == "l2r":
            print "Left to Right\n========="
            cipheredText = l2r(plainText,e,n)
            print "Ciphered Text is " + str(cipheredText)

            decipheredText = l2r(cipheredText,d,n)
            print "Deciphered Text is " + str(decipheredText) + "\n"

            print "Products done: " + str(counterProducts) + "\n"
            print "Squareds done: " + str(counterSqrts) + "\n"
            print "Hope: " + str((counterProducts+counterSqrts)/float(len(bin(e))))

        elif str(args[0]) == "r2l":
            print "Right to Left\n========="
            cipheredText = r2l(plainText, e, n)
            print "Ciphered Text is " + str(cipheredText)

            decipheredText = r2l(cipheredText, d, n)
            print "Deciphered Text is " + str(decipheredText) + "\n"

            print "Products done: " + str(counterProducts) + "\n"
            print "Squareds done: " + str(counterSqrts) + "\n"
            print "Hope: " + str((counterProducts+counterSqrts)/float(len(bin(e))))

        elif str(args[0]) == "slidingWindow":
            print "Sliding Windows\n========="
            cipheredText = slidingWindow(plainText, e, n)
            print "Ciphered Text is " + str(cipheredText)

            decipheredText = slidingWindow(cipheredText, d, n)
            print "Deciphered Text is " + str(decipheredText) + "\n"

            print "Products done: " + str(counterProducts) + "\n"
            print "Squareds done: " + str(counterSqrts) + "\n"
            print "Hope: " + str((counterProducts+counterSqrts)/float(len(bin(e))))

        elif str(args[0]) == "ladder":
            print "Montgomery Ladder\n========="
            cipheredText = monLadder(plainText, e, n)
            print "Ciphered Text is " + str(cipheredText)

            decipheredText = monLadder(cipheredText, d, n)
            print "Deciphered Text is " + str(decipheredText) + "\n"

            print "Products done: " + str(counterProducts) + "\n"
            print "Squareds done: " + str(counterSqrts) + "\n"
            print "Hope: " + str((counterProducts+counterSqrts)/float(len(bin(e))))

        elif str(args[0]) == "kary":
            print "K-ary\n========="
            cipheredText = kary(plainText, e, n)
            print "Ciphered Text is " + str(cipheredText)

            decipheredText = kary(cipheredText, d, n)
            print "Deciphered Text is " + str(decipheredText) + "\n"

            print "Products done: " + str(counterProducts) + "\n"
            print "Squareds done: " + str(counterSqrts) + "\n"
            print "Hope: " + str((counterProducts+counterSqrts)/float(len(bin(e))))

    else:
        print "ERROR: First argument must be a valid exponentiation method or -h/--help"
        printUsage()
