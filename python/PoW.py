import DSA
import hashlib
import sha3
import random
import pyprimes
import string
import math
import sys, os

# Write to the ChainFile!
# PoWLen = 6
# TxLen = 10
def PoW(TxBlockFileName, ChainFileName, PoWLen, TxLen):
    TxBlockFile = open(TxBlockFileName ,'r')
    if os.path.exists(ChainFileName) == True:
        ChainFile = open(ChainFileName, 'r')
    else:
        ChainFile = open(ChainFileName, 'w')
        ChainFile.close()
        ChainFile = open(ChainFileName, 'r')

    
    lines = TxBlockFile.readlines()
    TxCount = len(lines)/TxLen
    # Calculate hash of the root markle tree
    
    hashTree = []
    for i in range(0,TxCount):
        transaction = "".join(lines[i*TxLen:(i+1)*TxLen])
        hashTree.append(hashlib.sha3_256(transaction).hexdigest())

    t = TxCount
    j = 0
    while(t>1):
        for i in range(j,j+t,2):
            hashTree.append(hashlib.sha3_256(hashTree[i]+hashTree[i+1]).hexdigest())
        j += t
        t = t>>1
    rootHash = hashTree[2*TxCount-2]

    chainLines = ChainFile.readlines()

    ChainFile.close()
    ChainFile = open(ChainFileName, 'a')
    
    if len(chainLines) == 0:
        prev = "Day Zero Link in the Chain"
        nonce = random.getrandbits(128);

        temp = prev + '\n' + rootHash + '\n' + str(nonce) + '\n'

        PoW = hashlib.sha3_256(temp).hexdigest()
        while PoW[:6] != "000000":
            nonce = random.getrandbits(128)
            temp = prev + '\n' + rootHash + '\n' + str(nonce) + '\n'
            PoW = hashlib.sha3_256(temp).hexdigest()
        ChainFile.write(temp + PoW + '\n')
   
    else:
        prev = chainLines[-1][:-1]
        nonce = random.getrandbits(128);

        temp = prev + '\n' + rootHash + '\n' + str(nonce) + '\n'

        PoW = hashlib.sha3_256(temp).hexdigest()
        while PoW[:6] != "000000":
            nonce = random.getrandbits(128)
            temp = prev + '\n' + rootHash + '\n' + str(nonce) + '\n'
            PoW = hashlib.sha3_256(temp).hexdigest()
        ChainFile.write(temp + PoW + '\n')





    TxBlockFile.close()
    ChainFile.close()











    