from Crypto.Cipher import AES
import base64


def decrypt_ECB(key, ciphertext):
    aesECB = AES.new(key, AES.MODE_ECB)
    plaintext = aesECB.decrypt(ciphertext)
    print plaintext

def readFromFile(fileName):
    f= open(fileName,'r')
    text = f.read()
    return text

def main():
    ciphertext = base64.decodestring(readFromFile("7.txt"))
    decrypt_ECB("YELLOW SUBMARINE", ciphertext)

if __name__=="__main__":main()
