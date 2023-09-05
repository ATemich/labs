from random import randrange, randint
import json
	
def fastExp(a, b, n):
	res = 1 % n
	while b > 0:
		if b % 2 == 1:
			res = (res * a) % n
		a = (a * a) % n
		b //= 2
	return res

def miller_rabin(n):
	k = 100

	if n == 2 or n == 3:
		return True
	if n <= 1 or n % 2 == 0:
		return False

	r = 0
	d = n - 1
	while d % 2 == 0:
		r += 1
		d //= 2

	for i in range(k):
		a = randint(2, n - 2)
		x = pow(a, d, n)

		if x == 1 or x == n - 1:
			continue

		for j in range(r - 1):
			x = pow(x, 2, n)
			if x == n - 1:
				break
		else:
			return False

	return True
	
def evklid(a, b):
	if b == 0:
		return a, 1, 0

	nod, u1, v1 = evklid(b, a % b)
	x = v1
	y = u1 - (a // b) * v1
	return nod, x, y

def dgen(a, n):
	gcd, x, y = evklid(a, n)
	if gcd != 1:
		return False
	return x % n

def calculate_pq(n):
    factors = []
    for i in range(2, n):
        if n % i == 0:
            factors.append(i)
    return tuple(factors)

def calculate_d(e, phi):
    for i in range(2, phi):
        if (i * e) % phi == 1:
            return i

def pq_generator():
	f, s = 100, 1000
	p = randint(f, s)
	q = randint(f, s)

	while not miller_rabin(p):
		p = randint(f, s)
	while not miller_rabin(q):
		q = randint(f, s)

	return (p, q)

def generate_keypair(p, q):
	while not (miller_rabin(p) and miller_rabin(q)) and (p == q):
		pq_generator()
	
	n = p * q
	phi = (p - 1) * (q - 1)
	
	e = randrange(1, phi)

	while evklid(e, phi)[0] != 1:
		e = randrange(1, phi)
		
	d = dgen(e, phi)
	
	return ((n, e), (n, d))

def encrypt(public_key, plaintext, block_size=16):
	n, e = public_key
	blocks = block_size // 8
	ciphertext = []

	for i in range(0, len(plaintext), blocks):
		block = plaintext[i:i+blocks]
		ciphertext_block = fastExp(int.from_bytes(block.encode('utf-8'), byteorder='big'), e, n)
		ciphertext.append(ciphertext_block)

	return ciphertext

def decrypt(private_key, ciphertext, block_size=16):
	n, d = private_key
	blocks = block_size // 8
	message = []

	for ciphertext_block in ciphertext:
		block = fastExp(ciphertext_block, d, n)
		message_block = block.to_bytes(blocks, byteorder='big').decode('utf-8')
		message.append(message_block)

	return ''.join(message)

def decrypt2(private_key, ciphertext):
	d, n = private_key
	plaintext = [fastExp(char, d, n) for char in ciphertext]
	return plaintext

def decrypt3(d, n, ciphertext, block_size=16):
	blocks = block_size // 8
	message = []

	for ciphertext_block in ciphertext:
		block = pow(ciphertext_block, d, n)
		message_block = block.to_bytes(blocks, byteorder='big').decode('utf-8')
		message.append(message_block)

	return ''.join(message)

def hack(e, n, s):
	decrypted_temp = []
	decrypted = decrypt2((e, n), s)
	
	while decrypted != s:
		decrypted_temp = decrypted 
		decrypted = decrypt2((e, n), decrypted)   
		result = []
		for char in decrypted_temp:
			result.append(chr(char)) 
	return ''.join(result)

p, q = pq_generator()

public_key, private_key = generate_keypair(p, q)

file_path2 = "/Users/atemich/Desktop/Инфобез/Курсовая/output.txt"
file_path1 = "/Users/atemich/Desktop/Инфобез/Курсовая/input.txt"

file = open(file_path1, "r")
lines = file.readlines()
plaintext = lines[0].strip()
file.close()

ciphertext = encrypt(public_key, plaintext)
decrypted = decrypt(private_key, ciphertext)

file = open(file_path2, "w")
file.write(str(public_key[0]) + "\n")
file.write(str(public_key[0]) + "\n")
file.write(str(public_key[1]) + "\n")
file.write(str(ciphertext))
file.close()

print("Public key: ", public_key)
print("Private key: ", private_key)
print("Ciphertext: ", ciphertext)
print("Decrypted plaintext: ", decrypted)


file = open(file_path2, "r") 
lines = file.readlines()
n = int(lines[0].strip())
e = int(lines[1].strip())
s = json.loads(lines[2].strip())
file.close()
      
pq = calculate_pq(n)
phi = (pq[0] - 1) * (pq[1] - 1)
d = calculate_d(e, phi)

message = decrypt3(d, n, s)
print("Private key: (" + str(n) + ", " + str(d) + ")")
print("Decrypted plaintext: ", message)

result = hack(e, n, s)
print("Расшифрованный текст:", result)
