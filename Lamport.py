from hashlib import sha256
from os import urandom

#define errors
class InvalidInputLength(Exception): pass
class OneTimeKeyAlreadyUsed(Exception): pass
class InvalidSignature(Exception): pass

#TODO: put in util module
def splitString(byte_string, chunk_size):
	'''Splits string into chunk_size pieces'''
	num_chunks = len(byte_string)/chunk_size
	return [byte_string[chunk_size*i:chunk_size*(i + 1)] for i in range(num_chunks)]

def parseKey(byte_string):
	'''Splits key string into 256 pairs of 256 bits strings'''
	if len(byte_string) != 256*64:
		raise InvalidInputLength()
	#split into 256 pairs of 256-bit values
	parts = splitString(byte_string, 64)
	return [(p[:32], p[32:]) for p in parts]

def keyString(pairs):
	'''Concatinates pairs on key into string'''
	return ''.join([p[0] + p[1] for p in pairs])

def sha(byte_string):
	'''Computes the sha256 hash of input'''
	return sha256(byte_string).digest()

def iterateOverBits(byte_string):
	'''Wraps input to allow iteration over bits of string'''
	#iterate over each byte
	for b in byte_string:
		val = ord(b)
		#iterate over each bit
		for i in range(8):
			yield (val >> 7) & 1 #extract ith bit
			val = val << 1

class PublicKey:
	def __init__(self, byte_string):
		'''Create public key from 2*256*256 bit input string'''
		self.__key = parseKey(byte_string)

	def verify(self, message, signature):
		'''Verifies message signature and, if invalid raise error'''
		if len(signature) != 256*32:
			raise InvalidInputLength()
		h = sha(message)

		#split signature into 256 bit chunks (a signature for each bit of h)
		sig_parts = splitString(signature, 32)
	
		valid = True
		#check each piece of the signature
		for bit, sig, pair in zip(iterateOverBits(h), sig_parts, self.__key):
			if pair[bit] != sha(sig):
				valid = False
		if not valid:
			raise InvalidSignature()

	def __repr__(self):
		return 'public key:' + keyString(self.__key)

class PrivateKey:
	def __init__(self, byte_string, used=False):
		'''Create private key from 2*256*256 bit input string'''
		self.__key = parseKey(byte_string)
		self.__used = used

	def sign(self, message):
		'''Returns signature for message, or raises error if one time key
		has already been used'''
		if self.__used:
			raise OneTimeKeyAlreadyUsed()
		self.__used = True
		h = sha(message)
		parts = [pair[b] for b, pair in zip(iterateOverBits(h), self.__key)]
		return ''.join(parts)

	def used(self):
		'''Returns weither or not the one time signing key has been used'''
		return self.__used

	def __repr__(self):
		return 'private key:' + keyString(self.__key)

	def getPublicKey(self):
		'''Returns the public key corrisponding to this private key'''
		return PublicKey(keyString([(sha(p[0]), sha(p[1])) for p in self.__key]))

def gen(compute_public_key=True):
	'''Generates a Lamport one time signature key pair'''
	#NOTE: urandom is suitible for cryptographic random number generation
	#	see: https://docs.python.org/3/library/os.html#os.urandom
	sk = PrivateKey(urandom(256*2*32))
	pk = None
	#only compute public key if needed
	if compute_public_key:
		pk = sk.getPublicKey()
	return (sk, pk)

def test():
	sk, pk = gen()

	#test when public key generation is disabled
	sk2, pk2 = gen(False)
	assert(not pk2)

	#test that public and private keys match
	assert(str(sk.getPublicKey()) == str(pk))
	assert(not sk.used())

	#check key lengths
	assert(len(str(sk)) == 2*256*32 + len('private key:'))
	assert(len(str(pk)) == 2*256*32 + len('public key:'))

	msg = "From: Alice\nTo: Bank\nSubject: Send Bob $100"
	sig = sk.sign(msg)

	assert(sk.used())

	#test that private key can only be used once
	try:
		sk.sign('another message')
		assert(False) #should have raised key used error
	except Exception as e:
		assert(type(e) == OneTimeKeyAlreadyUsed)

	#check signature lenth
	assert(len(sig) == 256*32)

	#test verification
	pk.verify(msg, sig)

	#check for failure when message changes
	try:
		pk.verify('wrong message', sig)
		assert(False)
	except Exception as e:
		assert(type(e) == InvalidSignature)

	#check for failure when signature changes
	badSig = list(sig)

	#flip bit
	badSig[2] = chr(ord(badSig[2]) ^ 4)
	try:
		pk.verify(msg, ''.join(badSig))
		assert(False)
	except Exception as e:
		assert(type(e) == InvalidSignature)

if __name__ == '__main__':
	test()

