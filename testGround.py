from email.message import EmailMessage
from Cipher import AESCipher
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import hashlib
import smtplib
import base64
import random
import json
import os
import email
import imaplib

person1_email = os.environ.get('P1_EMAIL')
person1_pass = os.environ.get('P1_PASS')
person2_email = os.environ.get('P2_EMAIL')
person2_pass = os.environ.get('P2_PASS')

def send_quick_mail(sub,body,encrypt,sign):
    msg = EmailMessage()
    
    with smtplib.SMTP_SSL('smtp.gmail.com',465) as smtp:
        
        smtp.login(person1_email, person1_pass) #sender email and pass
       
        msg['Subject'] = str(sub) #setting subject
        msg['From'] = person1_email      #setting sender email
        msg['To'] = person2_email         #setting reciver email
        
        tempDic = {'EncryptionKey':'','Signature':''}
        
        if encrypt:
                #generatng aeskey
                AesKey = keyGen()
                
                #encrypting
                aes = AESCipher(AesKey)
                
                #TODO RSA encrypt with recipient public key before updating
                RSA_Encrypted_Key = RSA_Encryption(AesKey, 'p2')
                tempDic.update({'EncryptionKey':RSA_Encrypted_Key})
                
                print("Your msg is: %s\n\nThe AesKey is: %s\nFinal Hash is: %s\n"%(str(body),AesKey,aes.encrypt(str(body))))
                 
                msg.set_content(aes.encrypt(str(body)))
               
        else :
                tempDic.update({'EncryptionKey':"Unencrypted"})
                msg.set_content(str(body))
                
        if sign:
            tempDic.update({'Signature':sign_with_private(str(body), 'p1')})
            print("Signature: %s"%(tempDic['Signature']))
            
        else:
            tempDic.update({'Signature':'Unsigned'})   
            
        output_json(tempDic,msg)
        smtp.send_message(msg) #sender and reciver email

        print("Dic content: %s"%(tempDic))
        print("quick mail sended\n") 

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
    user_select = input("Enter 1 to Select Person 1\nEnter 2 to Select Person 2\n\n")
    
    while True:
        if str(user_select) == "1": #person 1
            print("person 1 selected\n")
            tempList = [person1_email,person2_email,person1_pass,'p1','p2']
            return(tempList)
                
        elif str(user_select) == "2": #person 2
            print("person 2 selected\n")
            tempList = [person2_email,person1_email,person2_pass,'p2','p1']
            return(tempList)
                
        else:
            print("Please Enter a Valid Input\n")           

def send_mail(tempList): 
    #pass in a list with following params:
    #[sender email,recipient email,sender app pass, selected user prefix for other methods]
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
        
        encryption_input = input("Enter 1 to Encypt your msg\nEnter 2 to Skip\n\n")
        while True:
            if str(encryption_input) == "1":
                #generatng aeskey
                AesKey = keyGen()
                
                #encrypting
                aes = AESCipher(AesKey)
                
                #TODO RSA encrypt with recipient public key before updating
                RSA_Encrypted_Key = RSA_Encryption(AesKey, tempList[3])
                tempDic.update({'EncryptionKey':RSA_Encrypted_Key})
                
                print("Your msg is: %s\n\nThe AesKey is: %s\nFinal Hash is: %s\n"%(str(body_input),AesKey,aes.encrypt(str(body_input))))
                 
                msg.set_content(aes.encrypt(str(body_input)))
                break
            
            elif str(encryption_input) == "2":
                tempDic.update({'EncryptionKey':"Unencrypted"})
                msg.set_content(str(body_input))
                break
            
            else:
                print("Please Enter a Valid Input\n")
                
        signing_input = input("Enter 1 to sign your msg\nEnter 2 to Skip\n\n")
        while True:
            if str(signing_input) == "1":
                tempDic.update({'Signature':sign_with_private(str(body_input), tempList[3])})
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

def keyGen(): #generates key for aes cipher
    Alphabet_Dic = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    Chars=[]
    AesKey = ""
                
    for i in range(12):
        Chars.append(random.choice(Alphabet_Dic))
                    
        AesKey = "".join(Chars)

    return AesKey

def sign_with_private(msg,person):#pass in the body text as str and sender prefixes
  
    message = bytes(msg,'utf-8')
    
    private_key = RSA.import_key(open(person + '_private_key.pem').read())
    hash_obj = SHA256.new(message)

    signer = PKCS1_v1_5.new(private_key)
    signature = signer.sign(hash_obj)
    
    base64_bytes = base64.b64encode(signature)
    print('signature after base64: %s\n'%(base64_bytes))
    
    sig_in_str = str(base64_bytes,'utf-8')
    
    print('b64 bytes of signature in str: %s\n'%(sig_in_str))
    
    return sig_in_str

def verify_with_public(sig_in_str,person,msg):#pass in signature in str format, sender prefixe, and msg recived to verify
    public_key = RSA.import_key(open(person + '_public_key.pem').read())
    
    b64_bytes = bytes(sig_in_str,'utf-8')
    signature = base64.b64decode(b64_bytes)
    
    message = bytes(msg,'utf-8')
    
    hash_obj = SHA256.new(message)

    try:
        PKCS1_v1_5.new(public_key).verify(hash_obj, signature)
        print ("The signature is valid.")
    except (ValueError, TypeError):
        print ("The signature is not valid.")

def output_json(tempDic,msg):#pass in a dictionary with all the info and msg from EmailMessage component
    # Create json attachment.
    attachment = json.dumps(tempDic)
                
    # Encode to bytes
    bs = attachment.encode('utf-8')

    # Attach
    msg.add_attachment(bs, maintype='application', subtype='json', filename='credentials.json')

def RSA_Encryption(aesKey,person):#pass in the aes key and the recipient person prefixes
    print("Key: %s"%(aesKey))
    public_key = RSA.import_key(open(person + '_public_key.pem').read())
    key_bytes = bytes(aesKey,'utf-8')
    
    hash_obj = PKCS1_OAEP.new(public_key)
    encrypted_key = hash_obj.encrypt(key_bytes)
    print("encrypted_key: %s\n"%(encrypted_key))
    
    base64_bytes = base64.b64encode(encrypted_key)
    print('Encrypted key after base64: %s\n'%(base64_bytes))
    
    key_in_str = str(base64_bytes,'utf-8')
    
    print('b64 bytes of key in str: %s\n'%(key_in_str))
    
    return key_in_str

def RSA_Decryption(key_in_str,person):#pass in encrypted key in str format and the recipientd person prefixes
    private_key = RSA.import_key(open(person + '_private_key.pem').read())
    
    b64_bytes = bytes(key_in_str,'utf-8')
    encrypted_key = base64.b64decode(b64_bytes)
    
    hash_obj = PKCS1_OAEP.new(private_key)
    decrypted_key = hash_obj.decrypt(encrypted_key)
    
    print("decrypted_key: %s\n"%(decrypted_key))
    
    key_in_str = str(decrypted_key,'utf-8')
    
    return key_in_str

#reciveing
host = 'imap.gmail.com' #inbox

def get_inbox_test(tempList):#codes from the documentation with modification
    mail = imaplib.IMAP4_SSL(host)                                      #server
    mail.login(tempList[0], tempList[2])                                #login user name, user pass
    mail.select("inbox")                                                #defualt inbox
    
    _, search_data = mail.search(None, 'UNSEEN')                        #underscore is used to skip the first data in the tuple(data with no use)
    my_message = []
    
    for num in search_data[0].split():                                  #turning bytes returned from search data in to a list of byte based on spaces(defualt)
        email_data = {}
        _, data = mail.fetch(num, '(RFC822)')                           #getting the msg data from gmail
        _, b = data[0]                                                  #data in bytes
        
        email_message = email.message_from_bytes(b)                     #turnind byte into str

        for header in ['subject', 'to', 'from', 'date']:
            print("{}: {}".format(header, email_message[header]))
            email_data[header] = email_message[header]
            #print("in header parsing")
            
        for part in email_message.walk():
            if part.get_content_type() == "application/json":
                fname = part.get_filename()
                print("saving file")
                with open(fname,'wb') as f:
                    f.write(part.get_payload(decode=True))
     
        my_message.append(email_data)
        
        #getting the body byte, turn it into str, then remove extra bits
        body_text = get_body(email_message)
        body_text = str(body_text, 'utf-8')
        body_text = body_text.replace('\r', '')
        body_text = body_text.replace('\n', '')
        credentials_scheme(body_text, tempList)
    
    return my_message
        
def read_json(value):
    with open('credentials.json', 'r') as cred_file:
        Recived_Credential = json.load(cred_file)
    return Recived_Credential[value]

def get_body(msg):
    if msg.is_multipart():
        return get_body(msg.get_payload(0))
    
    else: 
        return msg.get_payload(None,True)
    
def search(key, value, con): #returns result byte matches the search parameter that can be put in get_email
    result, data = con.search(None, key,'"()"'.format(value))
    return data

def get_emails(result_bytes):
    msgs = []
    
    for num in result_bytes[0].split():
        typ, data = con.fetch(num, '(RFC822)')
        msgs.append(data)
        
    return msgs

def inbox_menu(tempList): #main method for reciving
    con = imaplib.IMAP4_SSL(host)                       #secured con
    con.login(tempList[0],tempList[2])                  #login to interface
    con.select('INBOX')
    
    #downlaod attachment
    
    
    #after getting credential 
    credentials_scheme()
    # os.remove("credentials.json") #remove credentials.json
    
def credentials_scheme(body_text,tempList):
    encryption_statues = read_json('EncryptionKey')
    signature_statues = read_json('Signature')
    
    if encryption_statues == "Unencrypted":
        if signature_statues == "Unsigned":
            print("Body: %s\n"%(body_text))
        
        else:
            print("Body: %s\n"%(body_text))
            verify_with_public(read_json('Signature'), tempList[4], body_text)
        
    else:
        #creating aes obj with decrypted key from credentials
        aes = AESCipher(RSA_Decryption(read_json('EncryptionKey'), 'p2'))
        
        decrypted = aes.decrypt(body_text)
        
        if signature_statues == "Unsigned":
            print("Body: %s\n"%(decrypted))
        
        else:
            print("Body: %s\n"%(decrypted))
            verify_with_public(read_json('Signature'), tempList[4], decrypted)
    
                
# pem_check()
# list = [person1_email,person2_email,person1_pass] 
# send_mail(user_select())

# print((RSA_Decryption(RSA_Encryption(keyGen(), 'p1'), "p1")))

# send_mail(user_select())
# inbox = get_inbox(user_select())
# print(inbox)
# sign_with_private("this is the msg", 'p1')
# verify_with_public(sign_with_private("this is the msg", "p1"), "p1","this is the msg")
# send_quick_mail('p1 to p2 quick_mail', 'test msg', True, True)

# print(read_json('EncryptionKey'))
# # RSA_Decryption(read_json('EncryptionKey'), 'p2')
# aes = AESCipher(RSA_Decryption(read_json('EncryptionKey'), 'p2'))
# print(aes.decrypt("31yWNjPjWxx7+CboBuYv32qeSm2jbj5w2X4R+yDfhYA="))
    
# print(read_json('Signature'))
# verify_with_public(read_json('Signature'), 'p1', aes.decrypt("31yWNjPjWxx7+CboBuYv32qeSm2jbj5w2X4R+yDfhYA="))

send_quick_mail("Quick Read", "Test Text", True, False)
get_inbox_test(user_select())