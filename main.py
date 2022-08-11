import hashlib
import smtplib
import random
import os.path
import os
from Cipher import AESCipher
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

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
        tempList = [person1_email,person2_email,person1_pass]
        return(tempList)
                
    elif str(user_select) == "2": #person 2
        print("person 2 selected\n")
        tempList = [person2_email,person1_email,person2_pass]
        return(tempList)
                
    else:
        print("Please Enter a Valid Input\n")
            
def send_mail(tempList):
    sub_input = input("Enter the Subject\n")
    body_input = input("Enter the Body\n")
    
    with smtplib.SMTP('smtp.gmail.com',587) as smtp:
        smtp.ehlo() 
        smtp.starttls() #traffic encryption
        smtp.ehlo() #re-establish as encrypted traffic
        
        print("Sender email: %s\nSender pass: %s\n"%(tempList[0], tempList[2]))
        smtp.login(tempList[0], tempList[2]) #sender email and pass
        
        encryption_input = input("Enter 1 to Encypt your msg\nEnter 2 to Skip\n")
        while True:
            if str(encryption_input) == "1":
                #generatng aeskey
                AesKey = keyGen()
                
                file_out = open("AesKey.txt", "wb")
                file_out.write(AesKey)#TODO encrytpt aes with rsa
                file_out.close()

                #encrypting
                hash_obj = AESCipher(AesKey)
                
                print("Your msg is: %s\n\nThe AesKey is: %s\nFinal Hash is: %s"%(str(body_input),AesKey,hash_obj.encrypt(str(body_input))))
                
                #TODO turn this part into json format and save to file then send the json file as attatchment, use body as special identifier(for now)
                
                msg = 'Subject: %s\n\n%s'%(str(sub_input),hash_obj.encrypt(str(body_input)))
                break
            elif str(encryption_input) == "2":
                msg = 'Subject: %s\n\n%s'%(str(sub_input),str(body_input))
                break
            else:
                print("Please Enter a Valid Input\n")
                
        #TODO get signing method from testground
        signing_input = input("Enter 1 to sign your msg\nEnter 2 to Skip\n")
        while True:
            if str(signing_input) == "1":
                pass
                break
            elif str(signing_input) == "2":
                msg = 'Subject: %s\n\n%s'%(str(sub_input),str(body_input))
                break
            else:
                print("Please Enter a Valid Input\n")

        print("Reciver email: %s\nmsg: %s\n"%(tempList[1], msg))
        smtp.sendmail(tempList[0], tempList[1], msg) #sender and reciver email
    
        print("message send\n")

def keyGen():
    Alphabet_Dic = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    Chars=[]
    AesKey = ""
                
    for i in range(12):
        Chars.append(random.choice(Alphabet_Dic))
                    
        AesKey = "".join(Chars)

    return AesKey


#app
while True:
    menu_select = input("Enter 1 to Send Email\nEnter 2 to Recive Email\nEnter 3 to Exit\n")
    
    with smtplib.SMTP('smtp.gmail.com',587) as smtp:
        if str(menu_select) == "1": #sending email
            send_mail(user_select())
        
        elif str(menu_select) == "2": #recive email
            print("Nothing here\n")
            #user_select()
            #todo recive method
        
        elif str(menu_select) == "3": #exit
            break
    
        else:
            print("Please Enter a Valid Input\n")