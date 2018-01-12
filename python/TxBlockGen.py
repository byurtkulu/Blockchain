
import DSA
import random

def GenTxBlock(p, q, g, count):
	transaction = ""
	temp = ""
	for i in range(count):
		alpha_payee, beta_payee = DSA.KeyGen(p,q,g)
		alpha_payer, beta_payer = DSA.KeyGen(p,q,g)
		
		temp += "*** Bitcoin transaction ***\n"
		temp += "Serial number: " + str(random.getrandbits(128)) + "\n"
		temp += "p: " + str(p) + "\n"
		temp += "q: " + str(q) + "\n"
		temp += "g: " + str(g) + "\n"
		temp += "Payer Public Key (beta): " + str(beta_payer) + "\n"
		temp += "Payee Public Key (beta): " + str(beta_payee) + "\n"
		temp += "Amount: " + str(random.randint(0, 1000)) + " Satoshi\n"
		r, s = DSA.SignGen(temp, p, q, g, alpha_payer, beta_payer);
		temp += "Signature (r): " + str(r) + '\n'
		temp += "Signature (s): " + str(s)  + '\n'
		transaction += temp
		temp = ""
	return transaction