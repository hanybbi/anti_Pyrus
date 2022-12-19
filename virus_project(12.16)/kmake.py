import sys
import zlib
import hashlib
import os

def main() :
    if len(sys.argv) != 2 :
        print ('Usage : kmake.py [file]')
        return

    fname = sys.argv[1]
    tname = fname

    fp = open(tname, 'rb')
    buf = fp.read()
    fp.close()

    buf2 = zlib.compress(buf)

    
    buf3 = 'KAVM'

    f = buf3
    for i in range(6) :
        md5 = hashlib.md5()
        md5.update(f.encode('utf-8'))
        f = md5.hexdigest()

    buf3 +=f

    kmd_name = fname.split('.')[0] + '.kmd'
    fp = open(kmd_name, 'wb')
    buf3 = buf3.encode('utf-8')
    fp.write(buf3)
    fp.close()

    print(fname, '->', kmd_name)
    
if __name__ == '__main__' :
    main()
