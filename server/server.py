"""
    server.py - host an SSL server that checks passwords

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 140
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names:
    Jacob Christiansen
    Nick Price
    Devin Murray
"""

import hashlib
import socket
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

host = "localhost"
port = 10001


# A helper function. It may come in handy when performing symmetric encryption
def pad_message(message):
    return message + " " * ((16 - len(message)) % 16)


# Write a function that decrypts a message using the server's private key
def decrypt_key(session_key):

    file = open("priv_key.pem", 'r')
    new_key = RSA.importKey(file.read())
    dec_key = new_key.decrypt(session_key)

    return dec_key


# Write a function that decrypts a message using the session key
def decrypt_message(client_message, session_key):
    cipher = AES.new(session_key)

    dec_msg = cipher.decrypt(client_message)
    return dec_msg


# Encrypt a message using the session key
def encrypt_message(message, session_key):
    cipher = AES.new(session_key)

    padded_msg = pad_message(message)
    enc_msg = cipher.encrypt(padded_msg)

    return enc_msg


# Receive 1024 bytes from the client
def receive_message(connection):
    return connection.recv(1024)


# Sends message to client
def send_message(connection, data):
    if not data:
        print("Can't send empty string")
        return
    if type(data) != bytes:
        data = data.encode()
    connection.sendall(data)


# A function that reads in the password file, salts and hashes the password, and
# checks the stored hash of the password to see if they are equal. It returns
# True if they are and False if they aren't. The delimiters are newlines and tabs
def verify_hash(user, password):
    try:
        reader = open("passfile.txt", 'r')
        for line in reader.read().split('\n'):
            line = line.split("\t")
            if line[0] == user:
                #append salt to password:
                passWithSalt = password + str(line[1])
                #hash the slated password:
                hashed = hashlib.sha1(passWithSalt.encode())
                hashed_password = hashed.hexdigest()
                return hashed_password == line[2]
        reader.close()
    except FileNotFoundError:
        return False
    return False


def main():
    # Set up network connection listener
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (host, port)
    print('starting up on {} port {}'.format(*server_address))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(server_address)
    sock.listen(1)

    try:
        while True:
            # Wait for a connection
            print('waiting for a connection')
            connection, client_address = sock.accept()
            try:
                print('connection from', client_address)

                # Receive encrypted key from client
                encrypted_key = receive_message(connection)

                # Send okay back to client
                send_message(connection, "okay")

                # Decrypt key from client
                plaintext_key = decrypt_key(encrypted_key)

                # Receive encrypted message from client
                ciphertext_message = receive_message(connection)

                # Decrypt message from client
                dec_message = decrypt_message(ciphertext_message, plaintext_key).decode()

                # Split response from user into the username and password
                user = dec_message.split()[0]
                password = dec_message.split()[1]

                # Encrypt response to client
                response = "User cannot be authenticated."
                if verify_hash(user, password):
                    response = "User " + user + " has been authenticated."
                
                ciphertext_response = encrypt_message(response, plaintext_key)

                # Send encrypted response
                send_message(connection, ciphertext_response)

            finally:
                # Clean up the connection
                connection.close()
    finally:
        sock.close()


if __name__ in "__main__":
    main()
