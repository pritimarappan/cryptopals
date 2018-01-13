
def singleByteXor(cipher_in_bytes):
    buildScore()
    n = len(cipher_in_bytes)
    
    scoreList = buildScore()
    max_score = 0.0
    plainText = ''
    finalKey = ''
    for key in range(32,125):
        xored = xor(cipher_in_bytes, (chr(key)*n).decode('ascii'))
        test_score=scoreText(xored, scoreList)
        if(test_score > max_score):
            max_score=test_score
            plainText = xored
            finalKey = key
    return chr(finalKey)

def xor(input1, input2):
    xored = "".join(chr(ord(x) ^ ord(y)) for x,y in zip(input1, input2))
    return xored

def buildScore():
    f= open("pride_prejudice.txt",'r')
    text = f.read()
    score_map = [0.0]*256
    for c in text:
        score_map[ord(c)]+=1
    text_len = len(text)
    for i in range(0,len(score_map)):
        score_map[i] = score_map[i]/text_len
    return score_map

def scoreText(str1, score_list):
    score = 0.0
    for c in str1:
        score += score_list[ord(c)]
    score = score/len(str1)
    return score
    
def main():
    cipher_in_bytes = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".decode("hex")
    singleByteXor(cipher_in_bytes)


if __name__ =="__main__":main()
