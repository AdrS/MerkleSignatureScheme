#!/usr/bin/python

import MerkleSignatureTree
import string
import sys
from os import urandom
from Lamport import splitString

def isHexString(s):
	return all(c in string.hexdigits for c in s)

def exitErr(msg):
	print msg
	sys.exit(1)

#boiler plate code for writing and parsing key + signature files
def genKeyPair(private_key_file, public_key_file, height):
	#pick key and iv for generation of one time keys
	key = urandom(16)
	iv = urandom(12)
	lc = MerkleSignatureTree.LeafCalc(height, key, iv)
	mss = MerkleSignatureTree.MerkleSignatureTree(lc)
	pk = mss.getPublicKey()

	with open(private_key_file, 'wb') as f:
		f.write('private key: %s\n' % key.encode('hex'))
		f.write('iv: %s\n' % iv.encode('hex'))
		f.write('height: %d\n' % height)
	
	with open(public_key_file, 'wb') as f:
		f.write('public key: %s\n' % pk.encode('hex'))

def openPubKey(path):
	with open(path, 'r') as f:
		l = f.read().strip()
	if not l.startswith('public key: ') or len(l) < 76:
		exitErr('error: bad public key')

	root_hash = l.split()[2]

	if not isHexString(root_hash) or len(root_hash) != 64:
		exitErr('error: bad public key file (invalid sha256 hash)')
	return root_hash.decode('hex')

def openPrivKey(path):
	with open(path, 'r') as f:
		parts = f.read().strip().split()
	if len(parts) < 7 or ['private', 'key:'] != parts[:2] or 'iv:' != parts[3] or 'height:' != parts[5]:
		exitErr('error: bad private key')
	#parse key
	if not isHexString(parts[2]) or len(parts[2]) != 2*16:
		exitErr('error: bad key')
	key = parts[2].decode('hex')
	
	#parse iv
	if not isHexString(parts[4]) or len(parts[4]) != 2*12:
		exitErr('error: bad iv')
	iv = parts[4].decode('hex')
	
	#parse height
	if not parts[6].isdigit():
		exitErr('errror: bad height')

	height = int(parts[6])
	
	return (key, iv, height)

def writeSig(sig, path):
	#sig = (pub.__repr__(), sigp, self.leaf, self.authPath[:])
	with open(path, 'w') as f:
		f.write('One time public key: %s\n' % sig[0].encode('hex'))
		f.write('One time signature: %s\n' % sig[1].encode('hex'))
		f.write('Leaf: %d\n' % sig[2])
		f.write('Auth path: %s\n' % ''.join(sig[3]).encode('hex'))

def openSig(path):
	with open(path, 'r') as f:
		parts = f.read().strip().split()
	if len(parts) < 14:
		exitErr('error: malformed')
	#parse one time key
	if parts[:4] != ['One', 'time', 'public', 'key:'] or len(parts[4]) != 32790 or not isHexString(parts[4]):
		exitErr('error: bad one time key')
	otk = parts[4].decode('hex')

	#parse one time signature
	if parts[5:8] != ['One', 'time', 'signature:'] or len(parts[8]) != 16384 or not isHexString(parts[8]):
		exitErr('error: malformed one time signature')

	sigp = parts[8].decode('hex')
	
	#parse leaf
	if parts[9] != 'Leaf:' or not parts[10].isdigit():
		exitErr('error: malformed leaf index')
	
	leaf = int(parts[10])
	if parts[11:13] != ['Auth', 'path:'] or len(parts[13]) % 64 or not isHexString(parts[13]):
		exitErr('error: malformed authentication path')
	
	authPath = splitString(parts[13].decode('hex'), 32)
	
	#sig = (pub.__repr__(), sigp, self.leaf, self.authPath[:])
	return (otk, sigp, leaf, authPath)

def usage():
	usage_string = '''
	usage:
	./demo -g <height> <private key file> <public key file>
	./demo -s <private key> <file> <signature file>
	./demo -v <public key> <file> <signature file>
	'''
	exitErr(usage_string)

if __name__ == '__main__':
	if len(sys.argv) != 5: usage()
	if sys.argv[1] in ('-g', '--generate-key-pair'):
		h = int(sys.argv[2])
		if h < 1 or h > 20:
			exitErr('error: height must be between 1 and 20')
		genKeyPair(sys.argv[3], sys.argv[4], h)
	elif sys.argv[1] in ('-s', '--sign'):
		#TODO: have it read the leaf index to use
		#read private key file
		key, iv, height = openPrivKey(sys.argv[2])
		lc = MerkleSignatureTree.LeafCalc(height, key, iv)
		mss = MerkleSignatureTree.MerkleSignatureTree(lc)

		#read message
		with open(sys.argv[3], 'rb') as f: data = f.read()

		writeSig(mss.sign(data), sys.argv[4])
	elif sys.argv[1] in ('-v', '--verify'):
		#read public key file
		pk = openPubKey(sys.argv[2])

		#read message
		with open(sys.argv[3], 'rb') as f: data = f.read()

		#read signature
		sig = openSig(sys.argv[4])

		try:
			MerkleSignatureTree.verify(data, sig, pk)
		except MerkleSignatureTree.InvalidSignature:
			exitErr('INVALID SIGNATURE!!!!')
		print 'signature valid'
	else:
		exitErr('error: unrecognized option')
