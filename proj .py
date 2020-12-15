#!/usr/bin/env python3
#
#   The goal of this project is to utilize regexes to
# preform email mining with imap client.
#
#   I decided to use python and the imap client with a
#gmail account to mine emails that may contain phishing
#or spam-like information and notify the user of the
#potential threat these emails may pose.


#higher order functions
import functools
#for managing emails
import email
#utilizing imap to read emails
import imaplib
#library for regular expresson
import re


gmail = imaplib.IMAP4_SSL('imap.gmail.com')
#I like to think I am funny, very happy google let me ':)' in the password
gmail.login('lmvogeldata@gmail.com', 'WillThisWork:)') #it also will not work as I have closed the account for security 
gmail.list()
gmail.select('inbox')
#pulling the most recent 10 emails to test for spam
is_valid, contents = gmail.uid('search', None, 'ALL')
last10_uids = contents[0].split()[-10:]

#recursive function storing to a dictionary
def get_emails(uids, emails = []):
    if not uids:
        return emails
    #we primarily care about the email contents now
    is_valid, contents = gmail.uid('fetch', uids[0], '(RFC822)')
    return get_emails(uids[1:],
                      emails +
                      [email.message_from_bytes(contents[0][1])])

email_info = get_emails(last10_uids)


#function to calculate/determine the threat level an email falls under
#and also math is threatening to me, thus math_threat, Thank you
def math_threat(email_info):
    threat = None
    if 0 < email_info['spam count'] <= 6:
        threat = 'Low'
    elif email_info['spam count'] > 6:
        threat = 'High'

    return threat


#Home of the primary regular expression/Regex utilization
def threat_lvl(email_str):
    spam_words = ["suspended", "locked", "bank", "update",
                  "statement", "personal", "click", "compromised", "deactivated",
                  "reactivate", "account", "alert", "confirm", "won", "winner",
                  "selected", "claim", "urgent", "disabled", "expire", "investment",
                  "refinance", "pre-approved", "croshi"]

    #dictionary of maps counting each spam word found in the email and as well as how
    #many times a single spam word is used
    email_info = dict(map(lambda x : [x,0], spam_words))
#nice
    #Regex that searches the email string for the sneder information
    sender = re.search('(?<=From: )([^\<]*)(?:\<)(\w+\@\w+\.\w+)(?=\>)', str(email_str))
    sender_name = sender.group(1)
    sender_addi = sender.group(2)
    #Regex that searches the email string for the emails subject
    subject = re.search('(?<=Subject: )([^\r\n]*)(?=[\r\n])', str(email_str))
    subject = subject.group(0)
    #assigning regex search results to new dictionary keys
    email_info['sender'] = sender_name
    email_info['sender address'] = sender_addi
    email_info['email subject'] = subject

    spam_count = 0
    for spam_word in spam_words :
        #utilized the findall regex to compare the email string contents with
        #the spam_words list to count the number of occurances
        match = re.findall(spam_word, str(email_str))
        email_info[spam_word] = len(match)
        spam_count += len(match)

    email_info['spam count'] = spam_count

    email_info['threat level'] = math_threat(email_info)

    return email_info


#a list for the 10 email's threat level
all_emails = []
for an_email in email_info:
    all_emails.append(threat_lvl(an_email))

for an_email in all_emails:
    print('Threat level: ', an_email['threat level'])
    print('Email Subject: ', an_email['email subject'])
    print('Sender: ',an_email['sender'], an_email['sender address'], '\n')
