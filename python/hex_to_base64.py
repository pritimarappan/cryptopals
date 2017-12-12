


def main():
    hex_input= raw_input("Enter hex string")
    encoded = hex_input.decode("hex").encode("base64")
    print encoded

if __name__ == "__main__": main()
