import socket
import sys
import time
import KeyManager as km
import LoginManager as lm

# Client socket and connection to server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 1600))

# Receives from server, checks for certificate
msg = s.recv(1024)
items = msg.split(b"|")
if items[-1] != b"Certificate":
    s.send(b"Close")  # Server not trusted
    s.close()
    sys.exit(0)

# Retrieves session key, generates private/public key pair, sends session key to server
keys = km.KeyManager()
serverSessionKey = keys.readPublicKey(items[0])
s.send(keys.getPublicKey())

# Leaves if server declines connection
resp = s.recv(1024)
if resp != b"Accept":
    s.close()
    sys.exit(0)

def sendToServer(plaintext):
    """Function to send message with signature to server"""
    signature = keys.signUsingPrivateKey(plaintext)
    encryptedText = keys.encrypt(plaintext, serverSessionKey)
    s.send(encryptedText)
    time.sleep(1)
    s.send(signature)


# Creates log-in manager
login = lm.LoginManager()
currentUser = None

# Loop infinitely until user is logged into the system
while True:
    cmd = input("What would you like to do? [R] for register, [L] for login, [Q] for quit. \n")

    # Quitting program
    if cmd.upper() == "Q":
        print("Exiting, goodbye!")
        s.send(b"Close")
        s.close()
        sys.exit(0)

    # Sending registration request with digital signature
    elif cmd.upper() == "R":
        username, password = login.registerNewUser()
        sendToServer(b"Register|" + username + b"|" + password)

        # Checks for response from server
        msg = s.recv(1024)
        sig = s.recv(1024)
        digest = keys.decryptUsingPrivateKey(msg)
        if digest == b"Registered" and keys.verifyUsingPublicKey(sig, digest, serverSessionKey):
            print("Successfully registered.")
        else:
            print("Failed to register. Username may be taken. Please try again.")

    # Sending login request with digital signature
    elif cmd.upper() == "L":
        username, password = login.loginUser()
        sendToServer(b"Login|" + username + b"|" + password)

        # Checks for response from server
        msg = s.recv(1024)
        sig = s.recv(1024)
        digest = keys.decryptUsingPrivateKey(msg)
        if digest == b"Authenticated" and keys.verifyUsingPublicKey(sig, digest, serverSessionKey):
            print("Successfully logged in.")
            currentUser = username
            break
        else:
            print("Failed to authenticate. Please try again.")

print("\n================== WELCOME ", currentUser.decode(), "=======================\n")

def userChat(userKeys, contactKey, contactName, chatting):
    """This function handles user chat functionality"""
    print("\n============== CHATTING WITH", contactName, "==============\n")

    def sendToClient(plaintext):
        """Function to send message with signature to another client through server"""
        signature = userKeys.signUsingPrivateKey(plaintext)
        encryptedText = userKeys.encrypt(plaintext, contactKey)
        s.send(encryptedText)
        time.sleep(1)
        s.send(signature)

    # Loop infinitely for chatting
    while True:
        if chatting:
            textMessage = input(">> ")
            sendToServer(b"SendingMessage|" + contactName.encode())
            time.sleep(0.1)
            sendToClient(textMessage.encode())
        else:
            txt = s.recv(1024)
            txtSig = s.recv(1024)
            txtDigest = userKeys.decryptUsingPrivateKey(txt)
            if userKeys.verifyUsingPublicKey(txtSig, txtDigest, contactKey):
                print("[", contactName, "] : ", txtDigest.decode())
            else:
                print("[", contactName, "] : BLOCKED MESSAGE")
                print("MESSAGE MAY HAVE BEEN ALTERED IN TRANSIT, CANNOT BE TRUSTED.")
        chatting = not chatting
    return


# Looping infinitely for user actions
while True:
    userChoice = input("Would you like to send a message? [Y] for yes, [N] for no. \n")

    # User chooses to send a message
    if userChoice.upper() == "Y":
        # User chooses who to contact, makes own keys
        contact = input("Who would you like to contact? \n")
        clientKeys = km.KeyManager()

        # Sends ping request and public key to server
        sendToServer(b"PingUser|" + contact.encode())
        s.send(clientKeys.getPublicKey() + b"|Certificate")

        msg = s.recv(1024)
        sig = s.recv(1024)
        digest = keys.decryptUsingPrivateKey(msg)
        dItems = digest.split(b"|")
        if keys.verifyUsingPublicKey(sig, digest, serverSessionKey):
            if dItems[0] == b"Not found":
                print("Could not find user, or user is offline. Please try again later.")
            elif dItems[0] == b"RequestAccept":
                contactKeyInfo = s.recv(1024)
                infoParts = contactKeyInfo.split(b"|")
                if infoParts[-1] != b"Certificate":
                    print("Received bad certificate, declining connection from unknown user")
                    sendToServer(b"RequestDecline")
                    continue
                contactKey = keys.readPublicKey(infoParts[0])
                userChat(clientKeys, contactKey, contact, True)
            elif dItems[0] == b"RequestDecline":
                print(contact, " declined to connect.")

    # User chooses to listen for messages
    elif userChoice.upper() == "N":
        # Loops infinitely, waits for messages for key exchange
        while True:
            print("Waiting for messages...")
            msg = s.recv(1024)
            sig = s.recv(1024)
            contactKeyInfo = s.recv(1024)
            infoParts = contactKeyInfo.split(b"|")
            if infoParts[-1] != b"Certificate":
                print("Received bad certificate, declining connection from unknown user")
                sendToServer(b"RequestDecline")
                continue
            contactKey = keys.readPublicKey(infoParts[0])
            digest = keys.decryptUsingPrivateKey(msg)
            dItems = digest.split(b"|")
            if dItems[0] == b"Request" and keys.verifyUsingPublicKey(sig, digest, serverSessionKey):
                print("Received request to connect from ", dItems[1].decode())
                prmpt = input("Would you like to talk? [Y] for yes, [N] for no. \n")
                if prmpt.upper() == "Y":
                    clientKeys = km.KeyManager()
                    sendToServer(b"RequestAccept|" + dItems[1])
                    time.sleep(0.1)
                    s.send(clientKeys.getPublicKey() + b"|Certificate")
                    userChat(clientKeys, contactKey, dItems[1].decode(), False)
                else:
                    sendToServer(b"RequestDecline|" + dItems[1])
            else:
                print("Recieved bad signature from server, or bad request")
                sendToServer(b"RequestDecline|" + dItems[1])

            choice = input("Continue listening? [Y] for yes, [N] for no.\n")
            if choice.upper() == "N":
                break

# disconnect the client 
s.close() 