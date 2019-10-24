#!/usr/bin/env python
import os
import sys
import csv
import matplotlib.pyplot as plt
plt.locator_params(axis='y', nbins=6)
import collections
import numpy as np

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
    print("Usage: \n'python cCCA.py [-h/--help]' to print this Usage\n'python cCCA.py tracesFolder' to attack the traces with CCA")
    exit()

def column(matrix, i):
    return [row[i] for row in matrix]

def subBytes(byte):
    return sBox[byte]

def addRoundBitKey(inB, keyB):
    return (inB ^ keyB)

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
            if not os.path.isdir(path):
                print("ERROR: Second argument must be a valid path to the output data file")
                printUsage()
            else:
                print("Arguments correctly provided")
                data = []

                r0 = []
                r1 = []
                r2 = []
                r3 = []
                r4 = []
                r5 = []
                r6 = []
                r8 = []
                r9 = []
                r10 = []
                minLenght = -1
                for file in os.listdir(path):
                    if os.path.isfile(os.path.join(path, file)):
                        print("File: " + str(file))
                        filename = file.split("-")
                        input = filename[1]
                        output = filename[2].split(".")[0]
                        print("Input: " + str(input))
                        print("Output: " + str(output))
                        filepath = os.path.join(path, file)
                        traces = []
                        pcs = []
                        idx = []
                        with open(filepath, 'r') as file:
                            trace_reader = csv.DictReader(file, delimiter='\t')
                            for t in trace_reader:
                                traces.append(t)

                        for i, t in enumerate(traces):
                            idx.append(i)
                            pcs.append(t["pc"])

                        counter = collections.Counter(pcs)

                        auxR1 = []
                        for pc, rep in counter.items():
                            if rep == 144:
                                auxR1.append(pc)

                        pcR1 = min(auxR1)
                        firstR1 = pcs.index(pcR1)  ### PRINCIPI DE L'AES (R1 primer PC)
                        print(str(firstR1))
                        lastR10 = len(pcs) - 1 - pcs[::-1].index(pcR1)  ### FINAL DE TOT L'AES (RONDA 10)
                        c = 0
                        for i, pc in enumerate(pcs[firstR1:lastR10]):
                            if pc == pcR1:
                                if c == 16:
                                    pcR2 = pcs[firstR1 + i - 1]
                                    lastR1 = firstR1 + i + 1
                                    break
                                else:
                                    c += 1

                        print(str(lastR1))
                        if minLenght == -1 or minLenght > (lastR1-firstR1):
                            minLenght = (lastR1-firstR1)

                        r0aux = []
                        r1aux = []
                        r2aux = []
                        r3aux = []
                        r4aux = []
                        r5aux = []
                        r6aux = []
                        r8aux = []
                        r9aux = []
                        r10aux = []
                        for t in traces[firstR1:lastR1]:
                            r0aux.append(int(t["r0"]))
                            r1aux.append(int(t["r1"]))
                            r2aux.append(int(t["r2"]))
                            r3aux.append(int(t["r3"]))
                            r4aux.append(int(t["r4"]))
                            r5aux.append(int(t["r5"]))
                            r6aux.append(int(t["r6"]))
                            r8aux.append(int(t["r8"]))
                            r9aux.append(int(t["r9"]))
                            r10aux.append(int(t["r10"]))
                        r0.append(r0aux)
                        r1.append(r1aux)
                        r2.append(r2aux)
                        r3.append(r3aux)
                        r4.append(r4aux)
                        r5.append(r5aux)
                        r6.append(r6aux)
                        r8.append(r8aux)
                        r9.append(r9aux)
                        r10.append(r10aux)

                        data.append([input,firstR1,lastR1])

                        '''
                        ### PRINT PLOTS ###
                        plt.plot(idx[firstR1:lastR1],pcs[firstR1:lastR1])
                        plt.yticks(np.arange(0,779,77), np.arange(int(pcR1),int(pcR2),77))
                        plt.grid(True)
                        plt.xlabel("Instruction")
                        plt.ylabel("PCs")
                        plotsFolder = os.path.join(path,"plots")
                        if not os.path.isdir(plotsFolder):
                            os.mkdir(plotsFolder)

                        plt.savefig(path+"plots/trace-"+input+"-"+output+".png", bbox_inches='tight')
                        plt.clf()
                        '''

                print("Finished analyzing traces !")

                correctKey = []
                for byte in range(0,32,2):
                    print("### Byte is: " + str(int(byte/2)) + " ###")
                    for key in range(256):
                        print("### Key is: " + str(key) + " ###")
                        outR1 = []
                        for d in data:
                            inB1 = int(d[0][byte:byte + 2], 16)
                            outR1.append(subBytes(addRoundBitKey(inB1, key)))
                        for trace in range(minLenght):
                            # Getting lines from output
                            corrCoefR0 = np.corrcoef(outR1, column(r0, trace))[0][1]
                            if corrCoefR0 > 0.85 or corrCoefR0 < -0.85:
                                print("Correct key for byte " + str(int(byte/2)) + " was found in register 0 and is: " + str(key))
                                correctKey.append(key)
                                break
                            corrCoefR1 = np.corrcoef(outR1, column(r1, trace))[0][1]
                            if corrCoefR1 > 0.85 or corrCoefR1 < -0.85:
                                print("Correct key for byte " + str(int(byte/2)) + " was found in register 1 and is: " + str(key))
                                correctKey.append(key)
                                break
                            corrCoefR2 = np.corrcoef(outR1, column(r2, trace))[0][1]
                            if corrCoefR2 > 0.85 or corrCoefR2 < -0.85:
                                print("Correct key for byte " + str(int(byte/2)) + " was found in register 2 and is: " + str(key))
                                correctKey.append(key)
                                break
                            corrCoefR3 = np.corrcoef(outR1, column(r3, trace))[0][1]
                            if corrCoefR3 > 0.85 or corrCoefR3 < -0.85:
                                print("Correct key for byte " + str(int(byte/2)) + " was found in register 3 and is: " + str(key))
                                correctKey.append(key)
                                break
                            corrCoefR4 = np.corrcoef(outR1, column(r4, trace))[0][1]
                            if corrCoefR4 > 0.85 or corrCoefR4 < -0.85:
                                print("Correct key for byte " + str(int(byte/2)) + " was found in register 4 and is: " + str(key))
                                correctKey.append(key)
                                break
                            corrCoefR5 = np.corrcoef(outR1, column(r5, trace))[0][1]
                            if corrCoefR5 > 0.85 or corrCoefR5 < -0.85:
                                print(
                                    "Correct key for byte " + str(byte / 2) + " was found in register 5 and is: " + str(
                                        key))
                                correctKey.append(key)
                                break
                            corrCoefR6 = np.corrcoef(outR1, column(r6, trace))[0][1]
                            if corrCoefR6 > 0.85 or corrCoefR6 < -0.85:
                                print(
                                    "Correct key for byte " + str(byte / 2) + " was found in register 6 and is: " + str(
                                        key))
                                correctKey.append(key)
                                break
                            corrCoefR8 = np.corrcoef(outR1, column(r8, trace))[0][1]
                            if corrCoefR8 > 0.85 or corrCoefR8 < -0.85:
                                print(
                                    "Correct key for byte " + str(byte / 2) + " was found in register 8 and is: " + str(
                                        key))
                                correctKey.append(key)
                                break
                            corrCoefR9 = np.corrcoef(outR1, column(r9, trace))[0][1]
                            if corrCoefR9 > 0.85 or corrCoefR9 < -0.85:
                                print(
                                    "Correct key for byte " + str(byte / 2) + " was found in register 9 and is: " + str(
                                        key))
                                correctKey.append(key)
                                break
                            corrCoefR10 = np.corrcoef(outR1, column(r10, trace))[0][1]
                            if corrCoefR10 > 0.85 or corrCoefR10 < -0.85:
                                print(
                                    "Correct key for byte " + str(byte / 2) + " was found in register 10 and is: " + str(
                                        key))
                                correctKey.append(key)
                                break
                        else:
                            continue
                        break
                if len(correctKey) == 16:
                    print("Correct key found!: " + str(correctKey))
                else:
                    print("Correct key not found, just: " + str(correctKey))
    else:
        printUsage()