"""
    client.py - Connect to an SSL server

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 117
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names:
    Jacob Christiansen
    Nick Price
    Devin Murray
"""

import socket
import os
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA

host = "localhost"
port = 10001


# A helper function that you may find useful for AES encryption
# Is this the best way to pad a message?!?!
def pad_message(message):
    return message + " "*((16-len(message))%16)


# TODO: Generate a cryptographically random AES session key
def generate_key():
    new_key = os.urandom(16)

    return new_key


# Takes an AES session key and encrypts it using the server's public key:
def encrypt_handshake(session_key):

    file = open('pub_key.pem', 'r')
    new_key = RSA.importKey(file.read())
    enc_key = new_key.encrypt(session_key, 32)

    return enc_key


# Encrypts the message using AES. Same as server function
def encrypt_message(message, session_key):
    cipher = AES.new(session_key)
    padded_msg = pad_message(message)

    enc_msg = cipher.encrypt(padded_msg)

    return enc_msg


# Decrypts the message using AES. Same as server function
def decrypt_message(message, session_key):
    cipher = AES.new(session_key)
    dec_msg = cipher.decrypt(message)

    return dec_msg


# Sends a message over TCP
def send_message(sock, message):
	sock.sendall(message)


# Receive a message from TCP
def receive_message(sock):
    data = sock.recv(1024)
    return data


def main():
    user = input("What's your username? ")
    password = input("What's your password? ")

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = (host, port)
    print('connecting to {} port {}'.format(*server_address))
    sock.connect(server_address)

    try:
        # Message that we need to send
        message = user + ' ' + password

        # Generate random AES key
        key = generate_key()

        # Encrypt the session key using server's public key
        encrypted_key = encrypt_handshake(key)

        # Initiate handshake
        send_message(sock, encrypted_key[0])

        # Listen for okay from server (why is this necessary?)
        if receive_message(sock).decode() != "okay":
            print("Couldn't connect to server")
            exit(0)

        # Encrypt message and send to server
        enc_message = encrypt_message(message, key)
        send_message(sock, enc_message)

        # Receive and decrypt response from server
        server_response= receive_message(sock)
        server_response = decrypt_message(server_response, key).decode()
        print("the server says: "+server_response)

    finally:
        print('closing socket')
        sock.close()


if __name__ in "__main__":
    main()
