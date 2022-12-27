from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import sys

Block_Size = 16
key = b"this is key12345"
iv = b"this is iv123456"

def encrypt_func(fname):
   aes = AES.new(key, AES.MODE_CBC, iv)
   f = open(fname, 'rb')
   text = f.read()
   f.close()
   
   fname = fname.split(".")[0]
   f = open(fname + ".kmd", 'wb')
   f.write(aes.encrypt(pad(text, Block_Size)))
   f.close()
   
if __name__ == '__main__' :
    if len(sys.argv) != 2 :
        print('Usage : antivirus.py [file]')
        exit(0)

    fname = sys.argv[1]

    encrypt_func(fname)
