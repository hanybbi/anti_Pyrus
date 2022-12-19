import hashlib
import os
import py_compile
import random
import shutil
import struct
import sys
import zlib
import k2rc4
import k2rsa
import k2timelib

def make(src_fname, debug=False) :
    fname = src_fname

    if fname.split('.')[1] == 'py' :
        py_compile.compile(fname)
        pyc_name = fname + 'c'
    else :
        pyc_name = fname.split('.')[0] + '.pyc'
        shutil.copy(fname, pyc_name)

    rsa_pu = k2rsa.read_key('key.pkr')
    rsa_pr = k2rsa.read_key('key.skr')

    if not(rsa_pr and rsa_pu) :
        if debug :
            print('ERROR : Cannot find the key files!')
        return False

    kmd_data = 'KAVM'

    ret_date = k2timelib.get_now_date()
    ret_time = k2timelib.get_now_time()

    val_date = struct.pack('<H', ret_date)
    val_time = struct.pack('<H', ret_time)

    reserved_buf = val_date + val_time + (chr(0) * 28)

    kmd_data += reserved_buf

    random.seed()

    while 1 :
        tmp_kmd_data = ''
        key = ''

        for i in range(16) :
            key += chr(random.randint(0, 0xff))

        e_key = k2rsa.crypt(key, rsa_pr)
        if len(e_key) != 32 :
            continue

        d_key = k2rsa.crypt(e_key, rsa_pu)

        if key == d_key and len(key) == len(d_key) :
            tmp_kmd_data += e_key

            buf1 = open(pyc_name, 'rb').read()
            buf2 = zlib.compress(buf1)

            e_rc4 = k2rc4.RC4()
            e_rc4.set_key(key)

            buf3 = e_rc4.crypt(buf2)

            e_rc4 = k2rc4.RC4()
            e_rc4.set_key(key)

            if e_rc4.crypt(buf3) != buf2 :
                continue

            tmp_kmd_data += buf3

            md5 = hashlib.md5()
            md5hash = kmd_data + tmp_kmd_data

            for i in range(3) :
                md5.update(md5hash)
                md5hash = md5.hexdigest()

            m = md5hash.decode('hex')

            e_md5 = k2rsa.crypt(m, rsa_pr)
            if len(e_md5) != 32 :
                continue

            d_md5 = k2rsa.crypt(e_md5, rsa_pu)

            if m == d_md5 :
                kmd_data += tmp_kmd_data + e_md5
                break

    ext = fname.find('.')
    kmd_name = fname[0:ext] + '.kmd'

    try :
        if kmd_data :
            open(kmd_name, 'wb').write(kmd_data)
            os.remove(pyc_name)

            if debug :
                print('    Success : ', fname, '%-13s -> ', kmd_name)
            return True

        else :
            raise IOError
    except IOError :
        if debug :
            print('    Fail : ', fname)
        return False

    
        
