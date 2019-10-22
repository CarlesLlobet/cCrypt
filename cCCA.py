#!/usr/bin/env python
import os
import sys
import csv
import matplotlib.pyplot as plt
import collections

def printUsage():
    print("Usage: \n'python cCCA.py [-h/--help]' to print this Usage\n'python cCCA.py tracesFolder' to attack the traces with CCA")
    exit()

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

                # Getting lines from output
                for file in os.listdir(path):
                    if os.path.isfile(os.path.join(path,file)):
                        #file = "trace-0111e0d01cb6241bb7bff4f54458132c-c818704a609c7bc3057b81ab71e0321d.dat.idat"
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

                        for i,t in enumerate(traces):
                            idx.append(i)
                            pcs.append(t["pc"])

                        counter=collections.Counter(pcs)

                        auxR1 = []
                        for pc,rep in counter.items():
                            if rep == 144:
                                auxR1.append(pc)

                        pcR1 = min(auxR1)
                        firstR1 = pcs.index(pcR1) ### PRINCIPI DE L'AES (R1 primer PC)
                        print(str(firstR1))
                        lastR10 = len(pcs) - 1 - pcs[::-1].index(pcR1) ### FINAL DE TOT L'AES (RONDA 10)
                        c = 0
                        for i,pc in enumerate(pcs[firstR1:lastR10]):
                            if pc == pcR1:
                                if c == 16:
                                    pcR2 = pc
                                    lastR1 = firstR1+i+1
                                    break
                                else:
                                    c += 1

                        print(str(lastR1))

                        ### PRINT PLOTS ###
                        '''
                        plt.plot(idx[firstR1:lastR1],pcs[firstR1:lastR1])
                        plt.xlabel("Instruction")
                        plt.ylabel("PCs")
                        plotsFolder = os.path.join(path,"plots")
                        if not os.path.isdir(plotsFolder):
                            os.mkdir(plotsFolder)

                        plt.savefig(path+"plots/trace-"+input+"-"+output+".png", bbox_inches='tight')
                        plt.clf()
                        '''
    else:
        printUsage()