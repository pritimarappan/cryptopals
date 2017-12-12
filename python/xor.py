


def main():
    binary1 = raw_input("Enter hex input 1").decode("hex")
    binary2 = raw_input("Enter hex input 2").decode("hex")

    xored = "".join(chr(ord(x) ^ ord(y)) for x,y in zip(binary1, binary2))
    print xored.encode("hex")

if __name__ == "__main__": main()
