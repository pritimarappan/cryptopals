import 7


def findString(content):
    for line in content:
        blocks=[]

        for i in range(0, len(line)):
            blocks.append(line[i:i+16])
        
        for block in blocks:
            
    

def readFromFile(fileName):
    with open(fname) as f:
    content = f.readlines()
    content = [x.strip() for x in content]

def main():
    

if __name__=="__main__":main()
