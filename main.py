#pyright: reportMissingModuleSource=false
#pyright: reportMissingImports=false

#defined imports
import os
import time
import hashlib
import base58
import ecdsa
import codecs
from bitcoin import privtopub, pubtoaddr
from ecdsa.keys import SigningKey
from utilitybelt import dev_random_entropy
from binascii import hexlify, unhexlify

#defined functions
def saveFile(filename, data):
    fileP = open(filename, "w+", encoding="UTF-8")
    fileP.write(data)
    fileP.close()

def clearConsole():
    if os.name == "nt": os.system("cls")
    else: os.system("clear")

def randomExponent(curveOrder):
    while True:
        randomHex = hexlify(dev_random_entropy(32))
        randomInt = int(randomHex, 16)
        if 1 <= randomInt < curveOrder:
            return randomInt

def double_hash(key):
    return hashlib.sha256(hashlib.sha256(key).digest()).digest()

def genPrivateKey():
    curve = ecdsa.curves.SECP256k1
    secretExponent = randomExponent(curve.order)
    fromSecretExponent = ecdsa.keys.SigningKey.from_secret_exponent
    return hexlify(fromSecretExponent(secretExponent, curve, hashlib.sha256).to_string())

def genPrivateKeyWIF(privateKeyHex):
    privateKeyAndVersion = b"80" + privateKeyHex
    privateKeyAndVersion = codecs.decode(privateKeyAndVersion, 'hex')
    checksum = double_hash(privateKeyAndVersion)[:4]
    hashed = privateKeyAndVersion + checksum
    return base58.b58encode(hashed)

def getKeyPair():
    privateKeyHex = genPrivateKey()
    privateKey = privateKeyHex.decode('UTF-8')
    privateKeyWIF = genPrivateKeyWIF(privateKeyHex).decode('UTF-8')
    publicKey = privtopub(privateKey)
    address = pubtoaddr(publicKey)
    return privateKey, privateKeyWIF, publicKey, address

def main():
    clearConsole()
    print("Make Sure To Turn Wifi Off!")
    time.sleep(1)
    clearConsole()
    input("Press Enter To Start!")
    newKeyPair = getKeyPair()
    file = input("Enter Output File Path: ")
    data = f"Private Key: {newKeyPair[0]}\nPrivate Key WIF: {newKeyPair[1]}\nAddress: {newKeyPair[3]}"
    saveFile(file, data)
    clearConsole()
    input("Press Enter To Exit!")

main()