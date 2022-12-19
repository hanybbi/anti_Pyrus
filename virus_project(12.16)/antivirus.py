import sys
import os
import hashlib
import zlib
import io
import new

VirusDB = []
vdb = []
vsize = []

def DecodeKMD(fname) :
        fp = open(fname, 'rb')
        buf = fp.read()
        fp.close()

        buf2 = buf[:-32]
        buf = str(buf)
        fmd5 = buf[-33:-1]

        f = buf2
        for i in range(3) :
            md5 = hashlib.md5()
            if i == 0 :
                md5.update(f)
            else :
                md5.update(f.encode('utf-8'))
            f = md5.hexdigest()

        if f != fmd5 :
            raise SystemError

        buf3 = ''
        for c in buf2[4:] :
            c = chr(c)
            buf3 += chr(ord(c) ^ 0xFF)

        buf4 = zlib.decompress(buf3.encode('utf-8'))
        return buf4

def LoadVirusDB() :
    buf = DecodeKMD('virus.kmd')
    fp = io.StringIO(buf)

    while True :
        line = fp.readline()
        if not line : break

        line = line.strip()
        line = line.decode('utf-8')
        VirusDB.append(line)

    fp.close()

def MakeVirusDB() :
    for pattern in VirusDB :
        t = []
        v = pattern.split(':')
        t.append(v[1])
        t.append(v[2])
        vdb.append(t)

        size = int(v[0])
        if vsize.count(size) == 0 :
            vsize.append(size)

def SearchVDB(fmd5) :
    for t in vdb :
        if t[0] == fmd5 :
            return True, t[1]

    return False, ''


if __name__ == '__main__' :
    VirusDB = new.LoadVirusDB()
    vdb, vsize = new.MakeVirusDB(VirusDB)

    if len(sys.argv) != 2 :
        print('Usage : antivirus.py [file]')
        exit(0)

    fname = sys.argv[1]

    size = os.path.getsize(fname)
    if vsize.count(size) :
        fp = open(fname, 'rb')
        buf = fp.read()
        fp.close()

        m = hashlib.md5()
        m.update(buf)
        fmd5 = m.hexdigest()

        ret, vname = SearchVDB(fmd5)
        if ret == True :
            print(fname, ':', vname)
            #os.remove(fname)

        else :
            print(fname, ': ok')

    else :
            print(fname, ': ok')
