import sys
import zlib    # 압축을 위해 import
import hashlib


def main():
    if len(sys.argv) == 2:  # 커맨드 입력이 들어왔으면
        inputFile = sys.argv[1]      # 입력받은 내용으로 설정
    else:
        inputFile = raw_input('\nEnter input file : ')    # 아니면 사용자에게 입력을 받음

    fp = open(inputFile, 'rb')
    fbuf = fp.read()
    fp.close()

    compressed = zlib.compress(fbuf)
    cypherText = 'PJY'  # 헤더를 달아줌
    for c in compressed:    # 1byte(한 글자)씩 0xFF와 XOR - 암호화 알고리즘(Stream Cypher)
        cypherText += chr(ord(c)^0xFF)

    hashValue = cypherText
    # 해시를 3번 수행해준다
    for i in range(3):
        md5 = hashlib.md5()
        md5.update(hashValue)
        hashValue = md5.hexdigest()

    cypherText += hashValue      # 해시값을 뒤에 암호화된 내용 뒤에 더해준다
    outputFile = inputFile.split(' ')[0] + '.secure'    # 새로 만들어질 파일 이름

    fp = open(outputFile, 'wb')     # 쓰기 모드로 열기
    fp.write(cypherText)
    fp.close()

    print('Completed! %s -> %s' % (inputFile, outputFile))

if __name__ == '__main__':
    main()
