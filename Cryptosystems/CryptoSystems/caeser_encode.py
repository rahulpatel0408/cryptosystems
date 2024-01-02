string_upper='ABCDEFGHIJKLMNOPQRSTUVWXYZ'
string_lower='abcdefghijklmnopqrstuvwxyz'
number='0123456789'

def convert(letter,string,key):
    index=string.index(letter)
    index=(index+key)%len(string)
    return string[index]

def encoder(input_message,key,direction):
    key=key*(-1)**direction
    encode=''
    for letter in input_message:
        if letter in string_upper:
            letter=convert(letter,string_upper,key)
            encode+=letter
        elif letter in string_lower:
            letter=convert(letter,string_lower,key)
            encode+=letter
        elif letter in number:
            letter=convert(letter,number,key)
            encode+=letter
        else:
            encode+=letter
    return(encode)
def main():
    input_message=str(input("Enter your desired string"))
    key=int(input('enter key'))
    direction=bool(input("if right shift=0 if left shift=1"))

    print(encoder(input_message,key,direction))

if __name__=="__main__":
    main()
