#DISCLAIMER: this program is for educational purposes only, and should not be used in real-world applications

from Crypto.Util import number
import math
import random
from sympy import randprime

def encrypt(m, e, n):

    c = (m ** e) % n
    return c

def decrypt(c, d, n):
    
    m = (c ** d) % n
    return m

def keyGen():
    keySize = 8
    p = number.getPrime(keySize)
    q = number.getPrime(keySize)
    n = p * q
    phiOfN = (p-1) * (q-1)
    # generate e such that the GCD of e and phi(n) is 1
    # phi(n) is (p -1)(q-1) because n is the product of two prime numbers (See Euler's totient function)
    while True:
        e = random.randrange(2 ** (keySize -1), 2 ** (keySize))
        if math.gcd(e, phiOfN) == 1:
            break
    d = pow(e, -1, phiOfN)
    pk = (e, n)
    sk = (d, n)
    print(pk)
    print(sk)
    
    return e, d, n

def signatureOracle(m, d, n):
    signature = pow(m, d, n)
    return signature

def verify(signature, m, e, n):
    if m == pow(signature, e, n):
        return True
    else:
        return False

def CMAforgery(n):
    #select value (message) contained within the Group of Zn*
    m = randprime(1, n)
    #select other random value from same group
    m1 = randprime(1, n)
    m2 = m * pow(m1, -1, n) % n
    print("M (the target) =", m)
    print("M1 =", m1)
    print("M2 =", m2)
    return m, m1, m2

#Chosen Message Attack on UF-CMA Game under Text-book RSA

def ufCmaGameAttack():
    e, d, n = keyGen()
    m, m1, m2 = CMAforgery(n)                    #keyGen scheme produces public/secret keys pk, sk
    signature1 = signatureOracle(m1, d, n)
    print("Signature for M1: ", signature1)
    signature2 = signatureOracle(m2, d, n)
    print("Signature for M2: ", signature2)
    signatureForgery = (signature1 * signature2) % n
    print("Here is the signature forgery: (",m,",", signatureForgery,")" )      
    print(verify(signatureForgery, m, e, n))           #verification process results in True if a valid signature (or valid forgery), else False

#execute simulated attack
ufCmaGameAttack()
