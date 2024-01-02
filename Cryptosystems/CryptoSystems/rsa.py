import random
from Crypto.PublicKey import RSA
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import sys 				#To increase recursion limit since extended euclidian algo exceeds limit
sys.setrecursionlimit(1500)

# Pre generated primes
first_primes_list = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
					31, 37, 41, 43, 47, 53, 59, 61, 67,
					71, 73, 79, 83, 89, 97, 101, 103,
					107, 109, 113, 127, 131, 137, 139,
					149, 151, 157, 163, 167, 173, 179,
					181, 191, 193, 197, 199, 211, 223,
					227, 229, 233, 239, 241, 251, 257,
					263, 269, 271, 277, 281, 283, 293,
					307, 311, 313, 317, 331, 337, 347, 349]


def nBitRandom(n):
	return random.randrange(2**(n-1)+1, 2**n - 1)


def getLowLevelPrime(n):
	'''Generate a prime candidate divisible 
	by first primes'''
	while True:
		# Obtain a random number
		pc = nBitRandom(n)

		# Test divisibility by pre-generated
		# primes
		for divisor in first_primes_list:
			if pc % divisor == 0 and divisor**2 <= pc:
				break
		else:
			return pc


def isMillerRabinPassed(mrc):
	'''Run 20 iterations of Rabin Miller Primality test'''
	maxDivisionsByTwo = 0
	ec = mrc-1
	while ec % 2 == 0:
		ec >>= 1
		maxDivisionsByTwo += 1
	assert(2**maxDivisionsByTwo * ec == mrc-1)

	def trialComposite(round_tester):
		if pow(round_tester, ec, mrc) == 1:
			return False
		for i in range(maxDivisionsByTwo):
			if pow(round_tester, 2**i * ec, mrc) == mrc-1:
				return False
		return True

	# Set number of trials here
	numberOfRabinTrials = 20
	for i in range(numberOfRabinTrials):
		round_tester = random.randrange(2, mrc)
		if trialComposite(round_tester):
			return False
	return True


def random_prime(bits):
	while True:
		prime_candidate = getLowLevelPrime(bits)
		if not isMillerRabinPassed(prime_candidate):
			continue
		else:
			return prime_candidate

def generate_primes(bits):
	p=random_prime(bits)
	q=random_prime(bits)
	while p==q:
		q=random_prime(bits)
	return p,q


def gcd(a, b):
    if b == max(a, b):
        a, b = b, a  # Swap values

    while b != 0:
        divisor = b
        remainder = a % b
        a = b
        b = remainder

    return a




def get_e(phi):
    e = random.randrange(2, phi)
    
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)
    
    return e



def extended_euclid(phi, e):		#using extended euclidian algorithm
		
		if phi == 0:
			return e, 0, 1
		
		gcd, x1, y1 = extended_euclid(e % phi, phi)
		
		x = y1 - (e // phi) * x1
		y = x1
		

		return gcd, x, y

def get_d(tup, phi):		#here tup is output of extended euclid function

	d=tup[2]
	if d < 0 :
		d = d + phi
	
	elif d > phi :
		d = d % phi

	return d


def solve(base, exponent, modulus):
    result = 1

    base = base % modulus

    while exponent > 0:
        # If the current bit of exponent is 1, multiply result with base
        if exponent % 2 == 1:
            result = (result * base) % modulus 

        # Square the base and halve the exponent
        base = (base * base) % modulus 
        exponent //= 2

    return result

def rsa_encrypt(e, m, n):
	c = solve(m, e, n)

	return c

def rsa_decrypt(d, c, n):
	m = solve(c, d, n)

	return m

def pem_data(key):
	rsa_key = RSA.construct(key)
	pem_data = rsa_key.export_key(format='PEM', pkcs=8)
	return pem_data


def create_pem_file(key, output_file_path):
    
    rsa_key = RSA.construct(key)

    pem_data = rsa_key.export_key(format='PEM', pkcs=8)

    with open(output_file_path, 'wb') as file:
        file.write(pem_data)




def get_public_key_from_pem(pem_data):
    #(n, e)
    rsa_key = RSA.import_key(pem_data)

    e = rsa_key.e
    n = rsa_key.n
    public_key=(n,e)
    return public_key

def get_private_key_from_pem(pem_data):
    private_key = serialization.load_pem_private_key(pem_data, password=None, backend=default_backend())
    
    private_numbers = private_key.private_numbers()
    
    n = private_numbers.public_numbers.n
    e = private_numbers.public_numbers.e
    d = private_numbers.d
    p = private_numbers.p
    q = private_numbers.q
    
    key = (n, e, d, p, q)
    
    return key


def encrypt_msg(msg, public_key) :
	m = msg.encode('utf-8').hex()
	m = int(m, 16)
	c = rsa_encrypt(int(public_key[1]), m, int(public_key[0]))

	return c


def decrypt_msg(cipher_text, private_key) :
	m = rsa_decrypt(int(private_key[2]), int(cipher_text), int(private_key[0]))
	m = hex(m)[2:]
	decoded_text = bytes.fromhex(m).decode('utf-8')

	return decoded_text
 


def get_public_private_key(bits):
	
	p, q = generate_primes(bits)
	n = p * q
	phi = (p - 1) * (q - 1)
	
	e = get_e(phi)
	d = get_d(extended_euclid(phi, e), phi)
	
	return (n, e), (n, e, d, p, q)



def main():
	
	p,q=generate_primes(1024)  
	n = p*q				
	phi = (p-1)*(q-1)

	e = get_e(phi)
	d = get_d(extended_euclid(phi, e), phi)
	
	text = input("input")
	cipher_text = encrypt_msg(text, (n, e))
	decoded_text = decrypt_msg(cipher_text, (n, e, d, p, q) )
	print(decoded_text)

if __name__ == '__main__':
	main()

