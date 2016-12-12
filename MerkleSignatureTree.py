import Lamport
import struct
from Crypto.Cipher import AES

class InvalidInputLength(Exception): pass
class KeysAllUsed(Exception): pass
class InvalidSignature(Exception): pass
class InvalidLeafIndex(IndexError): pass
class MalformedSignature(InvalidSignature): pass

def lg(n):
	'''Calculates the binary logarithm of n'''
	l = 0
	while n > 1:
		l += 1
		n /= 2
	return l

def bytes2int(byte_string):
	return int(byte_string.encode('hex'), 16)

def int2bytes(i):
	return struct.pack(">I", i)

class OneTimeKeyGenerator:
	def __init__(self, key, iv):
		'''Generates pseudo random bytes for one time keys using AES-CTR mode
		key is 16 bytes, iv is 12 bytes'''
		if len(key) != AES.block_size or len(iv) != AES.block_size - 4:
			raise InvalidInputLength()
		self.__key = key
		self.__iv = iv
		self.__block_per_key = (256*2*32)/AES.block_size
		self.__cipher = AES.new(key, AES.MODE_ECB)

	def getOTK(self, i):
		'''returns part of stream for ith one time key'''
		#only handle leaves up to index ~2^24
		if (i * self.__block_per_key) > (1 << 31):
			raise InvalidLeafIndex()

		start = i * self.__block_per_key
		#generates blocks of random stream for one time key i
		blocks = []
		for j in range(start, start + self.__block_per_key):
			blocks.append(self.__cipher.encrypt(self.__iv + int2bytes(j)))
		return Lamport.PrivateKey(''.join(blocks))
		
class LeafCalc:
	def __init__(self, levels, key, iv):
		self.__gen = OneTimeKeyGenerator(key, iv)
		self.__N = 2**levels
		self.__levels = levels
		self.__cached_otk = None
		self.__cached_idx = -1
	
	def ensureLeafExists(self, i):
		'''ensures that ith otk is in internal cache'''
		if i >= self.__N:
			raise InvalidLeafIndex()
		#if leaf not in cache, regenerate it
		if self.__cached_otk != i:
			self.__cached_otk = self.__gen.getOTK(i)
			self.__cached_idx = i

	def getLeaf(self, i):
		#leaf is hash of one time public key
		return Lamport.sha(self.getPublicKey(i).__repr__())

	def getPublicKey(self, i):
		self.ensureLeafExists(i)
		return self.__cached_otk.getPublicKey()

	def getPrivateKey(self, i):
		self.ensureLeafExists(i)
		return self.__cached_otk
	
	def numLeaves(self):
		return self.__N
	
	def numLevels(self):
		return self.__levels

class TreeHash:
	def initialize(self, start, max_height):
		if start >= self.leafCalc.numLeaves():
			self.state = [(None, self.max_height)]
			return
			#raise InvalidLeafIndex()
		self.leaf = start
		#keep track of lowest height node (except at start and end)
		self.low = max_height
		self.max_height = max_height
		#stack to hold (node hash, node height) pairs
		self.state = []

	def __init__(self, start, max_height, leafCalc):
		self.leafCalc = leafCalc
		self.initialize(start, max_height)

	def done(self):
		return self.state and self.state[-1][1] == self.max_height
	
	def root(self):
		assert(self.done())
		return self.state[0][0]
	
	def update(self):
		if self.done():
			return
			print self.leafCalc.numLevels()
			print self.leaf
			print self.max_height
			print self.low
			print self.state
			assert(False)
		#if top two nodes have same height
		if len(self.state) >= 2 and self.state[-2][1] == self.state[-1][1]:
			right = self.state.pop()
			left = self.state.pop()
			#parent = hash(left || right)
			parent = Lamport.sha(left[0] + right[0])
			#height increases by 1
			height = right[1] + 1

			self.state.append((parent, height))
			self.low = height
		else:
			#add (leaf, 0 [the height of a leaf]) to stack
			self.state.append((self.leafCalc.getLeaf(self.leaf), 0))
			self.leaf += 1
			self.low = 0
		if self.done():
			self.low = (1 << 31) #set to infty

	def run(self):
		while not self.done(): self.update()
		return self.root()

class MerkleSignatureTree:
	def __init__(self, leafCalc):
		#start signing from first leaf
		self.leaf = 0
		self.leafCalc = leafCalc

		#calculate first authentication path
		height = leafCalc.numLevels()
		self.ths = [TreeHash(2 ** i, i, leafCalc) for i in range(height)]
		for th in self.ths: th.run()
		self.authPath = [th.root() for th in self.ths]

		#calculate root of tree (the public key)
		self.pk = leafCalc.getLeaf(0)
		for a in self.authPath:
			self.pk = Lamport.sha(self.pk + a)

		#start computation of future authentication paths
		for i, th in enumerate(self.ths):
			th.initialize(0, i)
			th.run()
	
	def sign(self, message):
		if self.leaf >= self.leafCalc.numLeaves():
			raise KeysAllUsed()
		#sign using one time key
		priv = self.leafCalc.getPrivateKey(self.leaf)
		pub = self.leafCalc.getPublicKey(self.leaf)
		sigp = priv.sign(message)

		#TODO: should tree parameters be part of signature???
		sig = (pub.__repr__(), sigp, self.leaf, self.authPath[:])


		#refresh auth nodes
		for h in range(self.leafCalc.numLevels()):
			#check if auth node at level needs refresh
			if (self.leaf + 1) % (2 ** h) == 0:
				self.authPath[h] = self.ths[h].root()

				start_node = (self.leaf + 1 + (1 << h)) ^ (1 << h)
				self.ths[h].initialize(start_node, h)

		#update stacks
		for th in self.ths:
			th.update()
			th.update()

		self.leaf += 1
		return sig

	def getPublicKey(self):
		return self.pk

def verify(message, signature, public_key):
	if len(signature) != 4: raise MalformedSignature()

	#extract one time signature public key
	try:
		binpub = signature[0][len("public key:"):]
		pub = Lamport.PublicKey(binpub)
	except Lamport.InvalidInputLength:
		raise InvalidSignature()
	#verify message against one time signature
	pub.verify(message, signature[1])

	authPath = signature[3]
	height = len(authPath)

	idx = int(signature[2])
	if idx < 0 or idx >= 2**height: raise MalformedSignature()

	cur_node = Lamport.sha(signature[0])

	#check authentication chain
	for a in authPath:
		if idx % 2:
			cur_node = Lamport.sha(a + cur_node)
		else:
			cur_node = Lamport.sha(cur_node + a)
		idx /= 2
	if cur_node != public_key: raise InvalidSignature()
	#TODO: put this function in public key class

def testTreeHash():
	key = 'a'*16
	iv = 'b'*12
	lc = LeafCalc(2, key, iv)
	l = [lc.getLeaf(i) for i in range(4)]
	i1 = Lamport.sha(l[0] + l[1])
	i2 = Lamport.sha(l[2] + l[3])
	rt = Lamport.sha(i1 + i2)

	#test for full tree
	th = TreeHash(0,2,lc)
	assert(th.leaf == 0)
	assert(th.state == [])
	assert(th.low == 2)
	th.update()
	assert(th.state == [(l[0], 0)])
	assert(th.low == 0)
	th.update()
	assert(th.state == [(l[0], 0), (l[1],0)])
	assert(th.low == 0)
	th.update()
	assert(th.state == [(i1, 1)])
	assert(th.low == 1)
	th.update()
	assert(th.state == [(i1, 1), (l[2], 0)])
	assert(th.low == 0)
	th.update()
	assert(th.state == [(i1, 1), (l[2], 0), (l[3], 0)])
	assert(th.low == 0)
	th.update()
	assert(th.state == [(i1, 1), (i2, 1)])
	assert(th.low == 1)
	th.update()
	assert(th.done())
	assert(th.root() == rt)
	assert(th.state == [(rt, 2)])
	assert(th.max_height == 2)

	#test for subtree
	th = TreeHash(2,1, lc)
	th.update()
	assert(th.state == [(l[2], 0)])
	th.update()
	assert(th.state == [(l[2], 0), (l[3], 0)])
	th.update()
	assert(th.done())
	assert(th.root() == i2)
	assert(th.state == [(i2, 1)])
	#TODO: finish me

def testOneTimeKeyGen():
	key = 'a'*16
	iv = 'b'*12
	c = AES.new(key, AES.MODE_ECB)
	gen = OneTimeKeyGenerator(key, iv)
	k0 = gen.getOTK(0).__repr__()[len('private key:'):]
	assert(len(k0) == 2*256*32)
	assert(c.encrypt(iv + '\x00'*4) == k0[:16])
	assert(c.encrypt(iv + '\x00\x00\x03\xff') == k0[-16:])

	k128 = gen.getOTK(128).__repr__()[len('private key:'):]
	assert(len(k128) == 2*256*32)
	assert(c.encrypt(iv + '\x00\x02\x00\x00') == k128[:16])
	assert(c.encrypt(iv + '\x00\x02\x03\xff') == k128[-16:])

	assert(gen.getOTK(1234).__repr__() == gen.getOTK(1234).__repr__())

def testMSS():
	from Lamport import sha
	key = 'a'*16
	iv = 'b'*12
	lc = LeafCalc(3, key, iv)
	l = [lc.getLeaf(i) for i in range(8)]
	l10 = sha(l[0] + l[1])
	l11 = sha(l[2] + l[3])
	l12 = sha(l[4] + l[5])
	l13 = sha(l[6] + l[7])
	l20 = sha(l10 + l11)
	l21 = sha(l12 + l13)
	rt  = sha(l20 + l21)

	mss = MerkleSignatureTree(lc)
	#check initial authentication path generation
	assert(mss.authPath == [l[1], l11, l21])
	assert(mss.ths[0].state == [(l[0], 0)])
	assert(mss.ths[1].state == [(l10, 1)])
	assert(mss.ths[2].state == [(l20, 2)])
	assert(mss.getPublicKey() == rt)

	m1 = "Message 1"
	sig1 = mss.sign(m1)

	verify(m1, sig1, mss.getPublicKey())

	#check that authentication path is updated
	assert(mss.authPath == [l[0], l11, l21])
	assert(mss.ths[0].state == [(l[3], 0)])
	assert(mss.ths[1].state == [(l10, 1)])
	assert(mss.ths[2].state == [(l20, 2)])

	m2 = "Message 2"
	sig2 = mss.sign(m2)
	verify(m2, sig2, mss.getPublicKey())

	assert(mss.authPath == [l[3], l10, l21])
	assert(mss.ths[0].state == [(l[2], 0)])
	assert(mss.ths[1].state == [(l[6], 0), (l[7], 0)])
	assert(mss.ths[2].state == [(l20, 2)])

	m3 = "Message 3"
	sig3 = mss.sign(m3)
	verify(m3, sig3, mss.getPublicKey())

	assert(mss.authPath == [l[2], l10, l21])
	assert(mss.ths[0].state == [(l[5], 0)])
	assert(mss.ths[1].state == [(l13, 1)])
	assert(mss.ths[2].state == [(l20, 2)])

	m4 = "Message 4"
	sig4 = mss.sign(m4)
	verify(m4, sig4, mss.getPublicKey())

	assert(mss.authPath == [l[5], l13, l20])
	assert(mss.ths[0].state == [(l[4], 0)])
	assert(mss.ths[1].state == [(l[4], 0), (l[5], 0)])
	#assert(mss.ths[2].state == [(l20, 2)])

	m5 = "Message 5"
	sig5 = mss.sign(m5)
	verify(m5, sig5, mss.getPublicKey())

	assert(mss.authPath == [l[4], l13, l20])
	assert(mss.ths[0].state == [(l[7], 0)])
	assert(mss.ths[1].state == [(l12, 1)])
	#assert(mss.ths[2].state == [(l20, 2)])


	lc = LeafCalc(10, key, iv)
	mss = MerkleSignatureTree(lc)
	for i in range(lc.numLeaves()):
		m = "Message %d" % i
		sig = mss.sign(m)
		verify(m, sig, mss.getPublicKey())
	#TODO: test verify
	#-malformed
	#1 time sig doesn't match
	#invalid authentication path
	
if __name__ == '__main__':
	testOneTimeKeyGen()
	testTreeHash()
	testMSS()
