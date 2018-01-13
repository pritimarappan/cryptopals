from itertools import cycle

def main():
    text = "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal"
    key = "ICE"
    repeatKeyXor(text,key)

def repeatKeyXor(text,key):
    xored = "".join(chr(ord(x) ^ ord(y)).encode('hex') for x,y in zip(text, cycle(key)))
    return xored

if __name__=="__main__":main()
