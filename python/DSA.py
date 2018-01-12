
# DSA.py

#------------------------------------------------------------------------------------------------------#
# A python function and its output file DSA params.txt which contains q, p, and g. 
# The format of the file must be the same as the example file DSA params.txt in the attachment.
#
#------------------------------------------------------------------------------------------------------#
#
# A python function and its output files DSA skey.txt and DSA pkey.txt 
# which contain (q, p, g, a), and (q, p, g, b), respectively.
# The formats of the files must be the same as the example files DSA skey.txt
# and DSA pkey.txt in the attachment.
#
#------------------------------------------------------------------------------------------------------#
#
# A python function and its output file SingleTransaction.txt. 
# See the example file Single-Transcation.txt file for details.
#
#------------------------------------------------------------------------------------------------------#
#
# A python function that reads SingleTransaction.txt file and 
# check if the signature is valid for this transaction.
#
#------------------------------------------------------------------------------------------------------#


import hashlib
import sha3
import random
import pyprimes
import string
import math
import sys

def rabinMiller(n):
     s = n-1
     t = 0
     while s&1 == 0:
         s = s/2
         t +=1
     k = 0
     while k<128:
         a = random.randrange(2,n-1)
         #a^s is computationally infeasible.  we need a more intelligent approach
         #v = (a**s)%n
         #python's core math module can do modular exponentiation
         v = pow(a,s,n) #where values are (num,exp,mod)
         if v != 1:
             i=0
             while v != (n-1):
                 if i == t-1:
                     return False
                 else:
                     i = i+1
                     v = (v**2)%n
         k+=2
     return True

def isPrime(n):
     #lowPrimes is all primes (sans 2, which is covered by the bitwise and operator)
     #under 1000. taking n modulo each lowPrime allows us to remove a huge chunk
     #of composite numbers from our potential pool without resorting to Rabin-Miller
     lowPrimes =   [3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97
                   ,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179
                   ,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269
                   ,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367
                   ,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461
                   ,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571
                   ,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661
                   ,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773
                   ,787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883
                   ,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997]
     if (n >= 3):
         if (n&1 != 0):
             for p in lowPrimes:
                 if (n == p):
                    return True
                 if (n % p == 0):
                     return False
             return rabinMiller(n)
     return False

def generateLargePrime(k):
     #k is the desired bit length
     r=100*(math.log(k,2)+1) #number of attempts max
     r_ = r
     while r>0:
        #randrange is mersenne twister and is completely deterministic
        #unusable for serious crypto purposes
         n = random.randrange(2**(k-1),2**(k))
         r-=1
         if isPrime(n) == True:
             return n
     return -1




def id_generator(size=10, chars=string.ascii_uppercase + string.digits):
	return ''.join(random.choice(chars) for _ in range(size))

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m




#-----------------------------------------------------------------





def DL_Param_Generator(small_bound, large_bound):
	s = small_bound.bit_length()
	l = large_bound.bit_length()
	q = generateLargePrime(s)
	while q == -1:
		q = generateLargePrime(s)

	p = 1

	while not (pyprimes.isprime(p) and p.bit_length() == l):
			r = random.getrandbits(l-s)
			p = q * r + 1
			if p.bit_length() == l-1:
				p = q*(r<<1)+1
			elif p.bit_length() == l+1:
				p = q*(r>>1)+1

	h = 2
	g = 1
	while g == 1:
		g = pow(h, (p-1)/q, p);
		h += 1
	
	#F=open("DSA_params.txt", 'w')
	#F.write(str(q)+'\n'+str(p)+'\n'+str(g)+'\n')
	#F.close()
	
	return (q, p, g)



def KeyGen(p, q, g):
	alpha = random.randint(0,q-1);
	beta = pow(g,alpha,p);
	#file = open("DSA_skey.txt", 'w')
	#file.write(str(q)+'\n'+ str(p)+'\n'+ str(g)+'\n'+ str(alpha)+'\n')
	#file.close()
	
	#file2 = open("DSA_pkey.txt", 'w')
	#file2.write(str(q)+'\n'+str(p)+'\n'+str(g)+'\n'+str(beta)+'\n')
	#file2.close()

	return (alpha, beta)


def SignGen(m, p, q, g, alpha, beta):
	h = int(hashlib.sha3_256(m).hexdigest(), 16)
	h = h % q
	k = random.randint(0,q-1);
	r = pow(g,k,p) % q
	s = ( alpha*r + k*h ) % q
	return (r,s)


def SignVer(m, r, s, p, q, g, beta):
	

	h = int(hashlib.sha3_256(m).hexdigest(), 16)
	h = pow(h, 1, q)
	v = modinv(h,q)
	z1 = pow(s*v, 1, q)
	z2 = pow((q-r)*v, 1, q)
	u =  pow(g,z1,p)*pow(beta,z2,p) % p

	if r == u%q:
		return 1;
	else:
		return 0;




"""
def create_single_transaction(message):
	
	q, p, g = DL_Param_Generator(1 << 256, 1 << 2048)
	alpha, beta = KeyGen(q, p, g);
	r, s = SignGen(message, q, p, g, alpha);

	ff = open("SingleTransaction.txt", 'w')
	ff.write("*** Bitcoin transaction ***\n")
	ff.write("Serial number: " + str(random.getrandbits(128)) + "\n")
	ff.write("Payer: " + id_generator() + "\n")
	ff.write("Payee: " + id_generator() + "\n")
	ff.write("Amount: " + str(random.randint(0, 1000)) + " Satoshi\n")
	ff.write("p: " + str(p) + '\n')
	ff.write("q: " + str(q) + '\n')
	ff.write("g: " + str(g) + '\n')
	ff.write("Public Key (beta): " + str(beta) + '\n')
	ff.write("Signature (r): " + str(r) + '\n')
	ff.write("Signature (s): " + str(s)  + '\n')
	ff.close()
"""














