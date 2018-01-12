import math
import random, string
import warnings
import sys, os
import pyprimes
import hashlib
import DSA, TxBlockGen, PoW

TxBlocksGenOn = 1    # set to 1 if you want to generate a block of bitcoin transaction
PoWGenOn = 1         # set to 1 if you want to provide PoW for given transaction blocks
BlockChainTestOn = 1 # set ot 1 if you want to validate the block chain
ValidateTxOn = 1     # set to 1 if you want to validate a transaction 

blockCount = 3 # number of link in the block chain (you can change)
TxCount = 8    # number of transactions in a block (you can change, but set it to a power of two)
PoWLen = 6     # the number of 0s in PoW (you can change)
TxLen = 10     # no of lines in a transaction (do not change)
LinkLen = 4    # no of lines in a link of the chain (do not change)

# Generate a random transaction along with its signature
if TxBlocksGenOn:
    if os.path.exists('DSA_params.txt') == True:
        inf = open('DSA_params.txt', 'r')
        q = int(inf.readline())
        p = int(inf.readline())
        g = int(inf.readline())
        inf.close()
        print "DSA parameters are read from file DSA_params.txt"
    else:
        print 'DSA_params.txt does not exist'
        sys.exit()
    
    FileName = "TransactionBlock"
    for i in range(0,blockCount):
        transaction=TxBlockGen.GenTxBlock(p, q, g, TxCount)
        TxBlockFileName = FileName+str(i)+".txt"
        TxBlockFile = open(TxBlockFileName, "w")
        TxBlockFile.write(transaction)
        TxBlockFile.close()
        print "Transaction block %d is written into TransactionBlock%d.txt" %(i,i)

# Proof of work generation for given transcation blocks
if PoWGenOn:
    FileName = "TransactionBlock"
    ChainFileName = "LongestChain.txt"
    for i in range(0,blockCount):
        TxBlockFileName = FileName+str(i)+".txt"
        if os.path.exists(TxBlockFileName) == True:
            PoW.PoW(TxBlockFileName, ChainFileName, PoWLen, TxLen)
            print "Proof of work is written/appended to "+ ChainFileName 
        else:
            print "Error: ", TxBlockFileName, "does not exist"
            sys.exit()
            

# Validate the block chain
if BlockChainTestOn:
    BlockChainFileName = "LongestChain.txt"
    if os.path.exists(BlockChainFileName) == True:
        BlockChainFile = open(BlockChainFileName, "r")
        blocks = BlockChainFile.readlines()
        blockCnt = len(blocks)/LinkLen
        PoW = blocks[LinkLen-1][:-1]
        
        if PoW != hashlib.sha3_256("".join(blocks[0:LinkLen-1])).hexdigest():
            print "Block chain does not validate:(( -A"
            sys.exit()

        if PoW[0:PoWLen] != "0"*PoWLen:
            print "Invalid proof of work:(("
            sys.exit()

        for i in range(1,blockCnt):
            PrevHash = blocks[LinkLen*i-1]
            if(PrevHash != blocks[LinkLen*i]):
                print "Block chain does not validate:(( -B"
                sys.exit()
            PoW = blocks[(i+1)*LinkLen-1][:-1]
            if PoW != hashlib.sha3_256("".join(blocks[i*LinkLen:(i+1)*LinkLen-1])).hexdigest():
                 print "Block chain does not validate:(( -C"
                 sys.exit()
            if PoW[0:PoWLen] != "0"*PoWLen:
                print "Invalid proof of work:(("
                sys.exit()     
                
        print "Block chain validates:))"
        BlockChainFile.close()
    else:
        print "Error: ", BlockChainFileName, "does not exist"
        sys.exit()


# Pick a random transaction in a random block and validate it
if ValidateTxOn:
    blockNo = random.randint(0,blockCount-1)
    txNo = random.randint(0,TxCount-1)

    print "Block no: ", blockNo
    print "Transaction no: ", txNo

    # open the transaction block file blockNo and read all transactions in it
    TxBlockFileName = "TransactionBlock"+str(blockNo)+".txt"
    if os.path.exists(TxBlockFileName) == False:
        print "Error: ", TxBlockFileName, "does not exist"
        sys.exit()
    
    TxBlockFile = open(TxBlockFileName, "r")
    lines = TxBlockFile.readlines()
    TxBlockFile.close()

    # read the transaction txNo from the file and verify its signature
    transaction = lines[txNo*TxLen:(txNo+1)*TxLen]
    SignedPart = "".join(transaction[0:TxLen-2])
    p = int(transaction[2][3:])
    q = int(transaction[3][3:])
    g = int(transaction[4][3:])
    beta = int(transaction[5][25:])
    r = int(transaction[8][15:])
    s = int(transaction[9][15:])
    if DSA.SignVer(SignedPart, r, s, p, q, g, beta)==1:
        print "The signature of the transaction verifies:))"
    else:
        print "The signature of the transaction does not verify:(("

    # Check if the transaction really belongs to that block
    # using "LongestChain.txt file"
    # The method is hash tree
    BlockChainFileName = "LongestChain.txt"
    if os.path.exists(BlockChainFileName) == False:
        print "Error: ", BlockChainFileName, "does not exist"
        sys.exit()
    BlockChainFile = open(BlockChainFileName, "r")
    blocks = BlockChainFile.readlines()
    # read the root hash from the BlockChainFileName file
    rootHash = blocks[LinkLen*blockNo+1]
    
    # compute the hash tree from the transaction
    # Construct the hash tree
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
    h = hashTree[2*TxCount-2]

    if h != rootHash[:-1]:
        print "Transaction does not belong to block number ", blockNo, ":(("
    else:
        print "Transaction belongs to block number ", blockNo, ":))"
    
    BlockChainFile.close()
