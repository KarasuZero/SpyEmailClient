import email
import getpass
import imaplib
import os
import sys

userName = 'yourgmail@gmail.com'
passwd = 'yourpassword'
directory = '/full/path/to/the/directory'


detach_dir = '.'
if 'DataFiles' not in os.listdir(detach_dir):
    os.mkdir('DataFiles')



try:
    imapSession = imaplib.IMAP4_SSL('imap.gmail.com')
    typ, accountDetails = imapSession.login(userName, passwd)
    if typ != 'OK':
        print('Not able to sign in!')
        raise

    imapSession.select('[Gmail]/All Mail')
    typ, data = imapSession.search(None, 'ALL')
    if typ != 'OK':
        print('Error searching Inbox.')
        raise


    for msgId in data[0].split():
        typ, messageParts = imapSession.fetch(msgId, '(RFC822)')
        if typ != 'OK':
            print('Error fetching mail.')
            raise

        emailBody = messageParts[0][1]
        mail = email.message_from_string(emailBody)
        for part in mail.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            if part.get('Content-Disposition') is None:
                continue
            fileName = part.get_filename()

            if bool(fileName):
                filePath = os.path.join(detach_dir, 'DataFiles', fileName)
                if not os.path.isfile(filePath) :
                    print(fileName)
                    fp = open(filePath, 'wb')
                    fp.write(part.get_payload(decode=True))
                    fp.close()
    imapSession.close()
    imapSession.logout()

    print('Done')


except :
    print('Not able to download all attachments.')