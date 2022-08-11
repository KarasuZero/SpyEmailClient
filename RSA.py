from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import os.path

#key exisitence check
private_key_exists = os.path.exists('private_key.pem')
public_key_exists = os.path.exists('public_key.pem')

print(private_key_exists)
print(public_key_exists)

#Generating key pairs

new_key = RSA.generate(2048)

private_key = new_key.exportKey("PEM")
public_key = new_key.publickey().exportKey("PEM")

fd = open("private_key.pem", "wb")
fd.write(private_key)
fd.close()

fd = open("public_key.pem", "wb")
fd.write(public_key)
fd.close()

#Encrypting with key

message = b'message'

#encrypting/signing
key = RSA.import_key(open('public_key.pem').read()) #reciver public key


hash_obj = PKCS1_OAEP.new(key)
ciphertext = hash_obj.encrypt(message) #output
print('cippher text: %s'%(ciphertext))


print("\n\n")


#decrypting
key = RSA.import_key(open('private_key.pem').read()) #reciver private key


hash_obj = PKCS1_OAEP.new(key)
plaintext = hash_obj.decrypt(ciphertext)
print ('decrypted: %s'%(plaintext.decode("utf-8")))