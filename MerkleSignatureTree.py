import Lamport

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

class LeafCalc:
	def __init__(self, levels):
		self.__N = 2**levels
		self.__levels = levels
		self.leaves = [None] * self.__N
	
	def ensureLeafExists(self, i):
		if i >= self.__N:
			raise InvalidLeafIndex()
		if self.leaves[i] == None:
			self.leaves[i] = Lamport.gen()

	def getLeaf(self, i):
		self.ensureLeafExists(i)
		#leaf is hash of one time public key
		return Lamport.sha(self.leaves[i][1].__repr__())

	def getPublicKey(self, i):
		self.ensureLeafExists(i)
		return self.leaves[i][1]

	def getPrivateKey(self, i):
		self.ensureLeafExists(i)
		return self.leaves[i][0]
	
	def numLeaves(self):
		return self.__N
	
	def numLevels(self):
		return self.__levels

class TreeHash:
	def initialize(self, start, max_height):
		if start >= self.leafCalc.numLeaves():
			raise InvalidLeafIndex()
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

		#get calculations going
		for i, th in enumerate(self.ths):
			th.initialize(0, i)
	
	def sign(self, message):
		if self.leaf >= self.leafCalc.numLeaves():
			raise KeysAllUsed()
		#sign using one time key
		priv = self.leafCalc.getPrivateKey(self.leaf)
		pub = self.leafCalc.getPublicKey(self.leaf)
		sigp = priv.sign(message)

		#TODO: should tree parameters be part of signature???
		sig = (pub.__repr__(), sigp, self.leaf, self.authPath[:])

		print self.leaf
		#update stacks
		for _ in range(2*self.leafCalc.numLevels() - 1):
			lows = [th.low for th in self.ths]
			lmin = min(lows)
			focus = lows.index(lmin)
			#update focused stack
			self.ths[focus].update()

		#refresh auth nodes
		for h in range(self.leafCalc.numLevels()):
			#check if auth node at level needs refresh
			if (self.leaf + 1) % (2 ** h) == 0:
				self.authPath[h] = self.ths[h].root()

				start_node = (self.leaf + 1 + (1 << h)) ^ (1 << h)
				self.ths[h].initialize(start_node, h)

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

class PublicKey:
	def __init__(self, tree_root):
		if len(tree_root) != 32:
			raise InvalidInputLength()
		self.__key = tree_root
	
	def verify(self, message, signature):
		#TODO: check signature length
		raise InvalidSignature()

def testTreeHash():
	lc = LeafCalc(2)
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

def testMSS():
	from Lamport import sha
	lc = LeafCalc(3)
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
	assert(mss.getPublicKey() == rt)

	m1 = "Message 1"
	sig1 = mss.sign(m1)
	verify(m1, sig1, mss.getPublicKey())

	#TODO: auth path updating does not work yet
	#check that authentication path is updated
	assert(mss.authPath == [l[0], l11, l21])

	m2 = "Message 2"
	sig2 = mss.sign(m2)
	verify(m2, sig2, mss.getPublicKey())

	lc = LeafCalc(10)
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
	testTreeHash()
	testMSS()
