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

def monosub_decoder(input_message,key):
    key=key.upper()
    
    
    dictionary = dict(zip(key,string_upper))
    decoded_message = ''
    for i in input_message :
        
        if i in string_upper:
            decoded_message += dictionary[i]
            continue
        
        elif i in string_upper.lower():
                i=i.upper()
                decoded_message += (dictionary[i]).lower()
        
        else:
            decoded_message+=i
            
    return decoded_message
    

    
        

def main():
    encoded_message=str(input("enter message to be encoded : "))
    key=str(input("Enter key :"))
    print(monosub_decoder(encoded_message,key))

if __name__=='__main__':
    main()