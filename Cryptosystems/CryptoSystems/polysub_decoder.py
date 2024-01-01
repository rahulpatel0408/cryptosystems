string_upper='ABCDEFGHIJKLMNOPQRSTUVWXYZ'
string_lower='abcdefghijklmnopqrstuvwxyz'


def full_key(input_string,key):
    long_key=''
    count=0
    for char in input_string:
        
        if char in string_upper:
            long_key+=key[count%len(key)]
            count+=1

        elif char in string_lower:
            long_key+=key[count%len(key)]
            count+=1

        else:
            long_key+=char

    return long_key

def polysub_decoder(input_string,key):
    while True:             #checking if key is alpha
        if key.isalpha():
            break
        else:
            key=input("Key Should contain alphabet only")


    key=key.upper()         #converting key to upper for simplicity
    
    long_key=full_key(input_string,key)   
    
    
    decoded=''
    for i in range(0,len(long_key)):
        
        if input_string[i] in string_upper:
            decoded_char=string_upper[(string_upper.index(input_string[i])-string_upper.index(long_key[i]))%26]
            decoded+=decoded_char
        
        elif input_string[i] in string_lower:

            decoded_char=string_upper[(string_lower.index(input_string[i])-string_upper.index(long_key[i]))%26]
            decoded+=decoded_char.lower()

        else:
            decoded+=input_string[i]
    
    return decoded

def main():
    input_string=str(input('message'))
    key=input('key')
    print(polysub_decoder(input_string,key))


if __name__=="__main__":
    main()