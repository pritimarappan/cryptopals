import set_1_3

def main():
    scoreList = set_1_3.buildScore()
    lines = [line.rstrip('\n') for line in open('1_4.txt')]
    max_score = 0.0
    plainText = ''
    ciphertext = ''
    for line in lines:
        for key in range(32,125):
            cipher_in_bytes = line.decode("hex")
            n = len(line)
            xored = set_1_3.xor(cipher_in_bytes, (chr(key)*n).decode('ascii'))
            test_score = set_1_3.scoreText(xored, scoreList)
            if(test_score > max_score):
                max_score=test_score
                plainText = xored
                ciphertext = line
    print plainText

if __name__=="__main__":main()
