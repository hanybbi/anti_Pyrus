import hashlib
import os
import sys

def decryptor(fileName):
    try:
        fp = open(fileName, 'rb')
        fbuf = fp.read()
        fp.close()

        cypherText = fbuf[:-32]      # 뒤에서 32글자만큼을 제외하고 잘라줌

        hashValue = cypherText
        # 해시를 3번 수행해준다
        for i in range(3):
            md5 = hashlib.md5()
            md5.update(hashValue)
            hashValue = md5.hexdigest()

        if hashValue != fbuf[-32:]:     # 뒤의 32글자와 해시값을 비교하여 다르면
            raise SystemError   # 시스템 에러를 발생시킴
        
        compressed = ''
        for c in cypherText[3:]:     # 헤더의 글자 수만큼 제외하고 잘라줌
            compressed += chr(ord(c) ^ 0xFF)    # XOR의 역함수는 XOR

        plainText = zlib.decompress(compressed)     # 압축을 풀어 평문을 얻음

        return plainText
    except:     # 오류발생 시 
        pass    # 아무것도 하지 않고
    
    return None     # None을 return

def loadDB(fileName):
    patterns = []
    fbuf = decryptor(fileName)      # 복호화
    fp = StringIO.StringIO(fbuf)    # readline()을 사용할 수 있도록 해줌

    while True:
        line = fp.readline()
        if not line: break  # 파일을 끝까지 읽으면 중단

        line = line.strip()     # 뒤에 붙어있는 엔터키 제거
        patterns.append(line)
    fp.close()

    return patterns

def makeDB(fileName):
    malwareDB = makeDB('patterns.db')
    sizeDB = map(lambda value: value[1], malwareDB.values())

    patterns = loadDB(fileName)
    for pattern in patterns:    # 파일로부터 한 줄씩
        p = pattern.split(':')  # 콜론 기준으로 자르기
        information = [p[1], int(p[2])]  # 각 악성코드에 대한 해시값과 파일 크기
        name = p[0]     # 악성코드 이름

        malwareDB[name] = information   # dictionary에 추가해줌

    return malwareDB

def searchDB(hashValue, malwareDB):
    for key, value in malwareDB.items():
        if value[0] == hashValue:
            return True, key
    return False, ''

def vaccine(fileLocation):
    malwareDB = makeDB('patterns.db.secure')
    sizeDB = map(lambda value: value[1], malwareDB.values())

    fp = open(fileLocation, 'rb')
    fileSize = os.path.getsize(fileLocation)
    if fileSize not in sizeDB:
        print fileLocation, ': Normal File'
        return

    fbuf = fp.read()
    fp.close()

    f = hashlib.md5()
    f.update(fbuf)
    hashValue = f.hexdigest()

    isMalware, name = searchDB(hashValue, malwareDB)
    if isMalware == True:
        print fileLocation, ': Malware(', name, ')'
        os.chmod(fileLocation, 0777)
        os.remove(fileLocation)
    else:
        print fileLocation, ': Normal File'

if __name__ == '__main__':
    if len(sys.argv) == 2:
        fileLocation = sys.argv[1]
    else:
        fileLocation = raw_input('\nPlease enter your file Location : ')
    vaccine(fileLocation)
