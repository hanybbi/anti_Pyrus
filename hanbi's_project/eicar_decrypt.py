# 복호화
import aes_decrypt

VirusDB = []
vdb = []
vsize = []

def LoadVirusDB() :
    db = aes_decrypt.decrypt_func('database.kmd')
    db = db.decode()

    for data in db.split():
        VirusDB.append(data)
    
    return VirusDB

def MakeVirusDB(VirusDB) :
    for pattern in VirusDB :
        t = []
        pattern_split = pattern.split(':')
        t.append(pattern_split[1])
        t.append(pattern_split[2])
        vdb.append(t)

        size = int(pattern_split[0])
        if vsize.count(size) == 0 :
            vsize.append(size)

    return vdb, vsize