
string_upper='ABCDEFGHIJKLMNOPQRSTUVWXYZ'
string_lower='abcdefghijklmnopqrstuvwxyz'
number='0123456789'





def convert(letter,string,key):
    index=string.index(letter)
    index=(index+key)%len(string)
    return string[index]

def decode(encoded_text,key):
    decoded_text=''
    for letter in encoded_text:
        if letter in string_upper:
            letter=convert(letter,string_upper,key)
            decoded_text+=letter
        elif letter in string_lower:
            letter=convert(letter,string_lower,key)
            decoded_text+=letter
        elif letter in number:
            letter=convert(letter,number,key)
            decoded_text+=letter
        else:
            decoded_text+=letter
    return decoded_text

def frequency(string_list):
        letter_frequency=[]
        for string in string_list:
            sum1=sum(string.lower().count(char) for char in 'aeot')
            sum2=sum(string.lower().count(char) for char in 'qjxz')
            total=sum1-sum2
            letter_frequency.append(total)
        return letter_frequency

def decoder(encoded_text,has_key,key):
    
    if has_key==0:
        string_list=[]
        for key in range(0,26):
            string_list.append(decode(encoded_text,key))
        letter_frequency=frequency(string_list)
        
        dictionary=dict(zip(string_list,letter_frequency))
        dictionary=dict(sorted(dictionary.items(), key=lambda item: item[1],reverse=True))
        
        count=1
        out ='List of all possible solutions in order of correctness: \n'
        for i in dictionary.keys():
            out += f"{count}. {i}\n"
            count+=1
        return out   
                

    if has_key==1:
        decoded_text1=decode(encoded_text,key)
        decoded_text2=decode(encoded_text,key*-1)
        
        return 'left shift: ' +  decoded_text1 + '\n' + 'right shift: ' + decoded_text2
    return 
if __name__=="__main__":
    encoded_text=str(input("Enter the encrypted message :   "))
    has_key=int(input("If you know key press 1 if you don't know key press 0"))
    if has_key == 1:    
        key = int(input("Enter Key"))
    print(decoder(encoded_text,has_key, key))