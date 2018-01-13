
import binascii
import set_1_3
import base64
import set_1_5

def main():
    
    ciphertext = readFromFile('6.txt')
    
    size = findKeySizes(ciphertext)
    
    text_chunks = breakCiphertext(size, ciphertext)
    blocks = transposeBlocks(size, text_chunks)
    
    key=[]
    
    for block in blocks:
        key.append(set_1_3.singleByteXor(block))
    print ''.join(key)
    
    hex_str= set_1_5.repeatKeyXor(base64.decodestring(ciphertext),''.join(key))
    print hex_str.decode("hex")
    
    


def computeHammingDistance(input1, input2):
    if len(input1) != len(input2):
        print "The 2 inputs are not of equal length"
    count =0
    for x,y in zip(input1,input2):
        if(x!=y):
            count+=1
    return count

def b64ToBin(inputStr):
    return "".join("{0:08b}".format(ord(c)) for c in base64.decodestring(inputStr))


def return_bytes(start,end,text):
    return text[start:end]

def readFromFile(fileName):
    f= open(fileName,'r')
    text = f.read()
    return text


def findKeySizes(ciphertext):
    keySizes=[]
    size = 0
    bestScore = 100000000000.0
    cipher_in_bytes = b64ToBin(ciphertext)
    for key_size in range(2,41):
        first_byte_chunk =  return_bytes(2,2+key_size*32,cipher_in_bytes)
        second_byte_chunk = return_bytes(2+key_size*32, 2+key_size*2*32, cipher_in_bytes)
        dist = computeHammingDistance(first_byte_chunk,second_byte_chunk)
        score = float(dist)/float(key_size)
        if score < bestScore:
            bestScore = score
            size = key_size
    print "key size " + str(size)
    return size


def breakCiphertext(keySize, ciphertext):
    textChunks=[]
    cipher_in_bytes = base64.decodestring(ciphertext)
    
    for i in range(0,len(cipher_in_bytes), keySize):
        textChunks.append(cipher_in_bytes[i:i+keySize])
    return textChunks


def transposeBlocks(keySize, textChunks):
    blocks=[]
    for i in range(0,keySize):
        ls=[]
        for chunk in textChunks:
            if(i<len(chunk)):
                ls.append(chunk[i])
        blocks.append(''.join(ls))
    return blocks


def testcomputeHammingDistance():
    print "testing Hamming compute"
    print computeHammingDistance(bin(int(binascii.hexlify("this is a test"),16)), bin(int(binascii.hexlify("wokka wokka!!!"),16)))
    


if __name__=="__main__":main()
