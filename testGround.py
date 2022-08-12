from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Cipher import AESCipher
import sys
import random
import os.path
import os
import base64
import hashlib
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from email.message import EmailMessage
import smtplib
import json

person1_email = os.environ.get('P1_EMAIL')
person1_pass = os.environ.get('P1_PASS')
person2_email = os.environ.get('P2_EMAIL')
person2_pass = os.environ.get('P2_PASS')

def pem_check():
    p1_private_key_exists = os.path.exists('p1_private_key.pem')
    p1_public_key_exists = os.path.exists('p1_public_key.pem')
    p2_private_key_exists = os.path.exists('p2_private_key.pem')
    p2_public_key_exists = os.path.exists('p2_public_key.pem')

    if p1_private_key_exists or p1_public_key_exists:
        print("p1 Keys found\n")
    else:
        print("p1 keys missing, generating...\n")
        pem_gen("p1")
        
    if p2_private_key_exists or p2_public_key_exists:
        print("p2 Keys found\n")
    else:
        print("p2 keys missing, generating...\n")
        pem_gen("p2")
              
def pem_gen(person): #pass in prefixes
    new_key = RSA.generate(2048)

    private_key = new_key.exportKey("PEM")
    public_key = new_key.publickey().exportKey("PEM")

    fd = open(person + "_private_key.pem", "wb")
    fd.write(private_key)
    fd.close()

    fd = open(person + "_public_key.pem", "wb")
    fd.write(public_key)
    fd.close()
    
def user_select(): #select user
    user_select = input("Enter 1 to Select Person 1\nEnter 2 to Select Person 2\n")
    
    if str(user_select) == "1": #person 1
        print("person 1 selected\n")
        tempList = [person1_email,person2_email,person1_pass,'p1']
        return(tempList)
            
    elif str(user_select) == "2": #person 2
        print("person 2 selected\n")
        tempList = [person2_email,person1_email,person2_pass,'p2']
        return(tempList)
            
    else:
        print("Please Enter a Valid Input\n")           

def send_mail(tempList):
    sub_input = input("Enter the Subject\n")
    body_input = input("Enter the Body\n")
    msg = EmailMessage()
    
    with smtplib.SMTP_SSL('smtp.gmail.com',465) as smtp:
        print("Sender email: %s\nSender pass: %s\n"%(tempList[0], tempList[2]))
        smtp.login(tempList[0], tempList[2]) #sender email and pass
        
        msg['Subject'] = str(sub_input) #setting subject
        msg['From'] = tempList[0]       #setting sender email
        msg['To'] = tempList[1]         #setting reciver email
        
        tempDic = {'EncryptionKey':'','Signature':''}
        
        encryption_input = input("Enter 1 to Encypt your msg\nEnter 2 to Skip\n")
        while True:
            if str(encryption_input) == "1":
                #generatng aeskey
                AesKey = keyGen()
                
                #encrypting
                aes = AESCipher(AesKey)
                tempDic.update({'EncryptionKey':AesKey})
                
                print("Your msg is: %s\n\nThe AesKey is: %s\nFinal Hash is: %s"%(str(body_input),AesKey,aes.encrypt(str(body_input))))
                 
                msg.set_content(aes.encrypt(str(body_input)))
                
                break
            elif str(encryption_input) == "2":
                tempDic.update({'EncryptionKey':"Unencrypted"})
                msg.set_content(str(body_input))
                break
            else:
                print("Please Enter a Valid Input\n")
                
        signing_input = input("Enter 1 to sign your msg\nEnter 2 to Skip\n")
        while True:
            if str(signing_input) == "1":
                
                tempDic.update({'Signature':sign_with_private(str(body_input), tempList[3]).hex()})
                print("Signature: %s"%(tempDic['Signature']))
                break
            
            elif str(signing_input) == "2":
                tempDic.update({'Signature':'Unsigned'})
                break
            else:
                print("Please Enter a Valid Input\n")

        output_json(tempDic,msg)
        smtp.send_message(msg) #sender and reciver email

        print("Dic content: %s"%(tempDic))
        print("message send\n")

def keyGen():
    Alphabet_Dic = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    Chars=[]
    AesKey = ""
                
    for i in range(12):
        Chars.append(random.choice(Alphabet_Dic))
                    
        AesKey = "".join(Chars)

    return AesKey

def sign_with_private(msg,person):
  
    message = bytes(msg,'utf-8')
    
    private_key = RSA.import_key(open(person + '_private_key.pem').read())
    hash_obj = SHA256.new(message)

    signer = PKCS1_v1_5.new(private_key)
    signature = signer.sign(hash_obj)

    print(signature.hex())

    return signature

def verify_with_public(signature,person,msg):
    public_key = RSA.import_key(open(person + '_public_key.pem').read())

    message = bytes(msg,'utf-8')
    hash_obj = SHA256.new(message)

    try:
        PKCS1_v1_5.new(public_key).verify(hash_obj, signature)
        print ("The signature is valid.")
    except (ValueError, TypeError):
        print ("The signature is not valid.")

def output_json(tempDic,msg):
    # Create json attachment.
    attachment = json.dumps(tempDic)
                
    # Encode to bytes
    bs = attachment.encode('utf-8')

    # Attach
    msg.add_attachment(bs, maintype='application', subtype='json', filename='credentials.json')

# pem_check()
# list = [person1_email,person2_email,person1_pass] 
send_mail(user_select())

# verify_with_public(sign_with_private("this is the msg", "p1"), "p1","this is the msg")