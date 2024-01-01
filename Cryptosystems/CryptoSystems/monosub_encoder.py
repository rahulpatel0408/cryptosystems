string_upper="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

def check_key(key):
    key = key.upper()
    seen_letters = set()
    for char in key: 
        if char in string_upper:
            if char in seen_letters:
                return 'Error: Key has repeating letters'
            else:
                seen_letters.add(char)
        else:
            return 'Error: Key must contain alpha-numeric characters only'
    if len(seen_letters)!= len(string_upper):
        return 'Error: Key is incomplete!!'
    else:
        return 'Key is Valid'


def monosub_encoder(input_message,key):
    key=key.upper()
    dictionary=dict(zip(string_upper,key))
    encoded_message=''
    for i in input_message :
        
        if i in string_upper:
            encoded_message += dictionary[i]
            continue
        
        elif i in string_upper.lower():
                i=i.upper()
                encoded_message += (dictionary[i]).lower()
        
        else:
            encoded_message+=i
    return encoded_message
    
    
    
        

def main():
    input_message=str(input("enter message to be encoded : "))
    key=str(input("Enter key :"))
    print(monosub_encoder(input_message,key))

if __name__=='__main__':
    main()