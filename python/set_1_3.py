


def main():
    ciphertext = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    cipher_in_bytes = ciphertext.decode("hex")
    n = len(ciphertext)

    for key in range(32,125):
        xored = xor(cipher_in_bytes, (chr(key)*n).decode('ascii'))
        
def xor(input1, input2):
    xored = "".join(chr(ord(x) ^ ord(y)) for x,y in zip(input1, input2))
    return xored

def score(candidate_str):
#TODO:

if __name__ =="__main__":main()
