import hashlib    # MD5를 구하기 위해 import
import os

fp = open('malwares\eicar.txt', 'rb')    # 반드시 바이너리 모드로 읽어들여 파일객체 생성
fbuf = fp.read()    # 파일객체로부터 내용 읽어들여 버퍼에 저장
fp.close()

f = hashlib.md5()    # MD5 hash function
f.update(fbuf)    # hashing!
hashValue = f.hexdigest()    # 메시지 다이제스트를 얻음(16진수 해시값)

if hashValue == '44d88612fea8a8f36de82e1278abb02f':    # EICAR test 파일의 MD5 해시값
    print '악성코드 발견!'
    os.chmod('malwares\eicar.txt', 0777)  # 파일이 읽기전용인 경우 chmod를 해주고
    os.remove('malwares\eicar.txt')    # 파일을 강제 삭제
else:
    print '악성코드가 없음'
