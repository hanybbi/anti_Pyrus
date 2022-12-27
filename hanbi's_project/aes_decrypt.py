from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import sys

Block_Size = 16
key = b"this is key12345"
iv = b"this is iv123456"

def decrypt_func(fname):

    aes = AES.new(key, AES.MODE_CBC, iv)
    f = open(fname, 'rb')
    text = f.read()
    f.close()

    msg = unpad(aes.decrypt(text), Block_Size)
    
    return msg