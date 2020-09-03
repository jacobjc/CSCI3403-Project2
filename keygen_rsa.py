from Crypto.PublicKey import RSA

key = RSA.generate(1024)


file = open('priv_key.pem','wb')
file.write(key.exportKey('PEM'))
file.close()


file = open('pub_key.pem', 'wb')
file.write(key.publickey().exportKey('PEM'))
file.close()
