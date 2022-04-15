from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from binascii import hexlify

def genClientKeys():
	private_key = RSA.generate(1024)
	public_key = private_key.publickey()
	
	private_pem = private_key.export_key().decode()
	public_pem = public_key.export_key().decode()

	with open('privateClient_pem.pem', 'w') as pr:
    		pr.write(private_pem)
	with open('publicClient_pem.pem', 'w') as pu:
    		pu.write(public_pem)
    		
def genServerKeys():
	private_key = RSA.generate(1024) 
	public_key = private_key.publickey()
	
	private_pem = private_key.export_key().decode()
	public_pem = public_key.export_key().decode()

	with open('privateServer_pem.pem', 'w') as pr:
    		pr.write(private_pem)
	with open('publicServer_pem.pem', 'w') as pu:
    		pu.write(public_pem)

    		
def loadClientPublicKey():
	pu_key = RSA.import_key(open('publicClient_pem.pem', 'r').read())
	
	return pu_key

def loadClientPrivateKey():
	pr_key = RSA.import_key(open('privateClient_pem.pem', 'r').read())
	
	return pr_key

def loadServerPublicKey():
	pu_key = RSA.import_key(open('publicServer_pem.pem', 'r').read())
	
	return pu_key

def loadServerPrivateKey():
	pr_key = RSA.import_key(open('privateServer_pem.pem', 'r').read())
	
	return pr_key
	
def encrypt(message,key):

	cipher = PKCS1_OAEP.new(key=key)
	encrypt_message = cipher.encrypt(message);
	
	return encrypt_message
	
def decryption(cipher_text,key):

	decrypt = PKCS1_OAEP.new(key=key)
	decrypted_message = decrypt.decrypt(cipher_text)
	return decrypted_message
