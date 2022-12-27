import os
import hashlib
import eicar_decrypt

class Main :
    def init(self, plugins_path) :
        return 0

    def uninit(self) :
        return 0

    def scan(self, filehandle, filename) :
        VirusDB = eicar_decrypt.LoadVirusDB()
        vdb, vsize = eicar_decrypt.MakeVirusDB(VirusDB)

        try:
            mm = filehandle
            size = os.path.getsize(filename)

            if vsize.count(size) :
                m = hashlib.md5()
                m.update(mm[:68])
                fmd5 = m.hexdigest()

                for t in vdb :
                    if t[0] == fmd5 :
                        return True, ' '+t[1], 0

        except IOError :
            pass

        return False, '', -1

    def disinfect(self, filename, malware_id) :
        try :
            if malware_id == 0 :
                os.remove(filename)
                return True

        except IOError :
            pass

        return False

    def listvirus(self) :
        vlist = list()

        vlist.append('EICAR-Test-File (not a virus)')

        return vlist

    def getinfo(self) :
        info = dict()

        info['author'] = 'Anti-Pyrus'
        info['version'] = '1.0'
        info['title'] = 'EICAR Scan Engine'
        info['kmd_name'] = 'eicar'
        info['sig_num'] = 1

        return info