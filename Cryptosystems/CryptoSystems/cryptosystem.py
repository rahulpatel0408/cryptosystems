import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
from caeser_decode import decoder
from caeser_encode import encoder
from monosub_decoder import monosub_decoder
from monosub_encoder import monosub_encoder, check_key, generate_mono_sub_key
from polysub_decoder import polysub_decoder
from polysub_encoder import polysub_encoder
from rsa import pem_data,get_public_key_from_pem, get_private_key_from_pem,encrypt_msg,decrypt_msg, get_public_private_key
from datetime import datetime


def save_to_history(encrypted_text, key, decrypted_text, cipher_name):
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with open('history.txt', 'a') as file:
        file.write(f'Time: {current_time}\n')
        file.write(f'Encrypted Text: {encrypted_text}\n')
        file.write(f'Key: {key}\n')
        file.write(f'Decrypted Text: {decrypted_text}\n')
        file.write(f'Cipher Name: {cipher_name}\n')
        file.write('\n\n\n') 

def save_generate_history(tup, bit):
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open('history.txt','a') as file:
        file.write(f'Time: {current_time}\n')
        file.write('Key Generation\n')
        file.write(f'Bit Size: {bit}\n')
        file.write(f'p: {tup[3]}\n')
        file.write(f'q: {tup[4]}\n')
        file.write(f'n: {tup[0]}\n')
        file.write(f'e: {tup[1]}\n')
        file.write(f'd: {tup[2]}\n')
        file.write('\n\n\n')



def wrap_text(text_widget):
        text_widget.config(wrap=tk.WORD)

def show_error_popup(error_message):
    messagebox.showerror(None, error_message)


def button_clicked(option):
    if option == "Exit":
        window.destroy()


    elif option == "Caesar Cipher":
        caesar_window()
        
    elif option == "Mono-Substitution Cipher":
         monosub_window()
    
    elif option == "Poly-Substitution Cipher":
        polysub_window()

    elif option == "RSA Encryption and Decryptyion":
        rsa_window()
    elif option == "History":
        show_history()   

'''caesar cipher'''
def caesar_window():
    def encrypt():
        input_text = decrypted_textbox.get("1.0", "end-1c")
        if not input_text:
            return
        try:
            encryption_key = int(key_encrypt_entry.get())
        except:
            show_error_popup("Enter Valid Key! Key must be integer")
            return 
        
        encrypted_text = encoder(input_text, encryption_key,1)
        encrypted_textbox.delete("1.0", "end")
        encrypted_textbox.insert("1.0", encrypted_text)

        save_to_history(encrypted_text, encryption_key, input_text, "Caesar Cipher")


    def decrypt():
        input_text = encrypted_textbox.get("1.0", "end-1c")
        if not input_text:
            return
        try:
            decryption_key = int(key_decrypt_entry.get())
        except:
            show_error_popup("Enter Valid Key! Key must be integer")
            return

        decrypted_text = decoder(input_text, 1, decryption_key)
        decrypted_textbox.delete("1.0", "end")
        decrypted_textbox.insert("1.0", decrypted_text)

        save_to_history(input_text, decryption_key, decrypted_text, "Caesar Cipher")


    def auto_decoder():
        input_text = encrypted_textbox.get("1.0", "end-1c")
        if not input_text:
            return
        decrypted_text = decoder(input_text, 0, None)
        decrypted_textbox.delete("1.0", "end")
        decrypted_textbox.insert("1.0", decrypted_text)

        save_to_history(input_text, "Auto_Decode", decrypted_text, "Caesar Cipher")


    def increase_key(entry):
        try:
            current_value = int(entry.get())
            entry.delete(0, tk.END)
            entry.insert(tk.END, str(current_value + 1))
        except:
            return

    def decrease_key(entry):
        try:
            current_value = int(entry.get())
            entry.delete(0, tk.END)
            entry.insert(tk.END, str(current_value - 1))
        except:
            return

    caesar_window = tk.Toplevel()
    caesar_window.geometry("900x600")
    caesar_window.title("Caesar Cipher Encryption Decryption Tool")

    # Left side - Encryption
    encrypt_frame = tk.Frame(caesar_window)
    encrypt_frame.pack(side=tk.LEFT, padx=10)

    tk.Label(encrypt_frame, text="Encrypted Text:").pack()
    encrypted_textbox = tk.Text(encrypt_frame, height=20, width=50, wrap="word")
    encrypted_textbox.pack(padx=10, pady=10)

    key_decrypt_frame = tk.Frame(encrypt_frame)
    key_decrypt_frame.pack()

    tk.Label(key_decrypt_frame, text="Key:").pack(side=tk.LEFT)
    key_decrypt_entry = tk.Entry(key_decrypt_frame, width=20)
    key_decrypt_entry.pack(side=tk.LEFT)
    key_decrypt_entry.insert(tk.END, "0")

    # "+" and "-" buttons for increasing and decreasing the key
    increase_button = tk.Button(key_decrypt_frame, text="+", command=lambda: increase_key(key_decrypt_entry))
    increase_button.pack(side=tk.RIGHT)

    decrease_button = tk.Button(key_decrypt_frame, text="-", command=lambda: decrease_key(key_decrypt_entry))
    decrease_button.pack(side=tk.LEFT)

    decrypt_button = tk.Button(encrypt_frame, text="Decrypt", command=decrypt)
    decrypt_button.pack()

    auto_decrypt = tk.Button(encrypt_frame, text="Auto Decrypt", command=auto_decoder)
    auto_decrypt.pack()

    # Right side - Decryption
    decrypt_frame = tk.Frame(caesar_window)
    decrypt_frame.pack(side=tk.LEFT, padx=10)

    tk.Label(decrypt_frame, text="Decrypted Text:").pack()
    decrypted_textbox = tk.Text(decrypt_frame, height=20, width=50, wrap="word")
    decrypted_textbox.pack(padx=10, pady=10)

    key_encrypt_frame = tk.Frame(decrypt_frame)
    key_encrypt_frame.pack()

    tk.Label(key_encrypt_frame, text="Key:").pack(side=tk.LEFT)
    key_encrypt_entry = tk.Entry(key_encrypt_frame, width=20)
    key_encrypt_entry.pack(side=tk.LEFT)
    key_encrypt_entry.insert(tk.END, "0")
    # "+" and "-" buttons for increasing and decreasing the key
    increase_button = tk.Button(key_encrypt_frame, text="+", command=lambda: increase_key(key_encrypt_entry))
    increase_button.pack(side=tk.RIGHT)

    decrease_button = tk.Button(key_encrypt_frame, text="-", command=lambda: decrease_key(key_encrypt_entry))
    decrease_button.pack(side=tk.LEFT)

    encrypt_button = tk.Button(decrypt_frame, text="Encrypt", command=encrypt)
    encrypt_button.pack()






'''monosubstitution cipher'''
def monosub_window():
    def encrypt():
        input_text = decrypted_textbox.get("1.0", "end-1c")
        if not input_text:
            return 
        
        encryption_key = (key_encrypt_entry.get())
        if check_key(encryption_key) != 'Key is Valid':
            show_error_popup(f"Error: {check_key(encryption_key)}")
            return
        
        encrypted_text = monosub_encoder(input_text, encryption_key)
        encrypted_textbox.delete("1.0", "end")
        encrypted_textbox.insert("1.0", encrypted_text)

        save_to_history(encrypted_text, encryption_key, input_text, "Mono Substitution Cipher")


    def decrypt():
        input_text = encrypted_textbox.get("1.0", "end-1c")
        if not input_text:
            return
        
        decryption_key = (key_decrypt_entry.get())
        if check_key(decryption_key) != 'Key is Valid':
            show_error_popup(f"Error: {check_key(decryption_key)}")
            return
        
        decrypted_text = monosub_decoder(input_text, decryption_key)
        decrypted_textbox.delete("1.0", "end")
        decrypted_textbox.insert("1.0", decrypted_text)

        save_to_history(input_text, decryption_key, decrypted_text, "Mono Substitution Cipher")


    def update_color(entry, alphabet_numbers_buttons):
        key = entry.get().lower()
        for char in alphabet_numbers_buttons:
            if key.count(char) == 1:
                alphabet_numbers_buttons[char]['bg'] = 'green'
            elif key.count(char) > 1:
                alphabet_numbers_buttons[char]['bg'] = 'red'
            else:
                alphabet_numbers_buttons[char]['bg'] = 'black'



    def button_command(char, entry, alphabet_numbers_buttons):
        entry.insert(tk.END, char)
        update_color(entry, alphabet_numbers_buttons)


    def generate_key():
        key = generate_mono_sub_key()
        key_encrypt_entry.delete(0, tk.END)
        key_encrypt_entry.insert(tk.END, key)


    monosub_window = tk.Tk()
    monosub_window.geometry("900x600")
    monosub_window.title("monosub Cipher Encryption Decryption Tool")

    # Left side - Encryption
    encrypt_frame = tk.Frame(monosub_window)
    encrypt_frame.pack(side=tk.LEFT, padx=10)

    tk.Label(encrypt_frame, text="Encrypted Text:").pack()
    encrypted_textbox = tk.Text(encrypt_frame, height=20, width=50, wrap="word")
    encrypted_textbox.pack(padx=10, pady=10)

    tk.Label(encrypt_frame, text="Key:").pack()
    key_decrypt_entry = tk.Entry(encrypt_frame, width=50)
    key_decrypt_entry.pack()
    

    decrypt_button = tk.Button(encrypt_frame, text="Decrypt", command=decrypt)
    decrypt_button.pack()

    # Alphabet and Numbers for Encryption
    alphabet_numbers_frame_encrypt = tk.Frame(encrypt_frame)
    alphabet_numbers_frame_encrypt.pack()

    alphabet_numbers_buttons_encrypt = {}

    for char in "abcdefghijklmnopqrstuvwxyz0123456789":
        button = tk.Button(alphabet_numbers_frame_encrypt, text=char, width=2, height=1, bg='black', fg='white', command=lambda c=char: button_command(c, key_decrypt_entry, alphabet_numbers_buttons_encrypt))
        button.grid(row="abcdefghijklmnopqrstuvwxyz0123456789".index(char) // 10, column="abcdefghijklmnopqrstuvwxyz0123456789".index(char) % 10)
        alphabet_numbers_buttons_encrypt[char] = button

    key_decrypt_entry.bind("<KeyRelease>", lambda event: update_color(key_decrypt_entry, alphabet_numbers_buttons_encrypt))

    # Right side - Decryption
    decrypt_frame = tk.Frame(monosub_window)
    decrypt_frame.pack(side=tk.LEFT, padx=10)

    tk.Label(decrypt_frame, text="Decrypted Text:").pack()
    decrypted_textbox = tk.Text(decrypt_frame, height=20, width=50, wrap="word")
    decrypted_textbox.pack(padx=10, pady=10)

    tk.Label(decrypt_frame, text="Key:").pack()
    key_encrypt_entry = tk.Entry(decrypt_frame, width=50)
    key_encrypt_entry.pack()
    key_encrypt_entry.insert(tk.END, "QWERTYUIOPLKJHGFDSAZXCVBNM7894561230")

    generate_key_button = tk.Button(decrypt_frame, text="Generate Key", command=generate_key)
    generate_key_button.pack()


    encrypt_button = tk.Button(decrypt_frame, text="Encrypt", command=encrypt)
    encrypt_button.pack()

    # Alphabet and Numbers for Decryption
    alphabet_numbers_frame_decrypt = tk.Frame(decrypt_frame)
    alphabet_numbers_frame_decrypt.pack()

    alphabet_numbers_buttons_decrypt = {}

    for char in "abcdefghijklmnopqrstuvwxyz0123456789":
        button = tk.Button(alphabet_numbers_frame_decrypt, text=char, width=2, height=1, bg='black', fg='white', command=lambda c=char: button_command(c, key_encrypt_entry, alphabet_numbers_buttons_decrypt))
        button.grid(row="abcdefghijklmnopqrstuvwxyz0123456789".index(char) // 10, column="abcdefghijklmnopqrstuvwxyz0123456789".index(char) % 10)
        alphabet_numbers_buttons_decrypt[char] = button

    key_encrypt_entry.bind("<KeyRelease>", lambda event: update_color(key_encrypt_entry, alphabet_numbers_buttons_decrypt))

    monosub_window.mainloop()    

    


def polysub_window():
    def encrypt():
        input_text = decrypted_textbox.get("1.0", "end-1c")
        if not input_text:
            return
        encryption_key = key_encrypt_entry.get()

        if encryption_key.isalpha() == False:    
            show_error_popup("Enter Valid Key! Key must contain alphabets only")
            return
        
        encrypted_text = polysub_encoder(input_text, encryption_key)
        encrypted_textbox.delete("1.0", "end")
        encrypted_textbox.insert("1.0", encrypted_text)

        save_to_history(encrypted_text, encryption_key, input_text, "Poly Substitution Cipher")

    def decrypt():
        input_text = encrypted_textbox.get("1.0", "end-1c")
        if not input_text:
            return
        decryption_key = key_decrypt_entry.get()
        
        if decryption_key.isalpha() == False:
            print(decryption_key, decryption_key.isalpha())    
            show_error_popup("Enter Valid Key! Key must contain alphabets only")
            return

        decrypted_text = polysub_decoder(input_text, decryption_key)
        decrypted_textbox.delete("1.0", "end")
        decrypted_textbox.insert("1.0", decrypted_text)

        save_to_history(input_text, decryption_key, decrypted_text, "Poly Substitution Cipher")

    polysub_window = tk.Toplevel(window)
    polysub_window.geometry("900x600")
    polysub_window.title("polysubstitution Cipher Encytption Decryption Tool")

    # Left side - Encryption
    encrypt_frame = tk.Frame(polysub_window)
    encrypt_frame.pack(side=tk.LEFT, padx=10)

    tk.Label(encrypt_frame, text="Encrypted Text:").pack()
    encrypted_textbox = tk.Text(encrypt_frame, height=20, width=50, wrap="word")
    encrypted_textbox.pack(padx=10,pady=10)


    tk.Label(encrypt_frame, text="Key:").pack()
    key_decrypt_entry = tk.Entry(encrypt_frame, width=40)
    key_decrypt_entry.pack()

    decrypt_button = tk.Button(encrypt_frame, text="Decrypt", command=decrypt)
    decrypt_button.pack()


    # Right side - Decryption
    decrypt_frame = tk.Frame(polysub_window)
    decrypt_frame.pack(side=tk.LEFT, padx=10)

    tk.Label(decrypt_frame, text="Decrypted Text:").pack()
    decrypted_textbox = tk.Text(decrypt_frame, height=20, width=50, wrap="word")
    decrypted_textbox.pack(padx=10,pady=10)

    tk.Label(decrypt_frame, text="Key:").pack()
    key_encrypt_entry = tk.Entry(decrypt_frame, width=40)
    key_encrypt_entry.pack()

    encrypt_button = tk.Button(decrypt_frame, text="Encrypt", command=encrypt)
    encrypt_button.pack()



'''RSA'''

def rsa_window():
    def button_clicked(option):
        if option == "Generate Public Private Key Pair":
            generate_key_pair()

        elif option == "Encrypt using key":
            rsa_encoder_window()

        elif option == "Decrypt using key":
            rsa_decoder_window()
        else:
            window.destroy()
    
    
    
    def generate_key_pair():
        
        

        def generate_keys_from_bits():
            try:    
                bits = int(bits_entry.get())

            except:
                show_error_popup("Bit Size must be integer value")
                return
            if bits > 1200:
                show_error_popup("Error: Computational limit exceeded. pass value less tha 1200 bits")
                return
            
            public_key, private_key = get_public_private_key(bits)

            publickey_int_textbox.delete('1.0', 'end')
            publickey_int_textbox.insert('1.0', f'n = {public_key[0]}\ne = {public_key[1]}')

            privatekey_int_textbox.delete('1.0', 'end')
            privatekey_int_textbox.insert('1.0', f'n = {private_key[0]}\ne = {private_key[1]}\nd = {private_key[2]}\np = {private_key[3]}\nq = {private_key[4]}')

            publickey_pem_textbox.delete('1.0', 'end')
            publickey_pem_textbox.insert('1.0', pem_data(public_key))

            privatekey_pem_textbox.delete('1.0', 'end')
            privatekey_pem_textbox.insert('1.0', pem_data(private_key)) 

            save_generate_history(private_key, bits)

        def save_file(text_box):

            file_path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM Files", "*.pem"), ("All Files", "*.*")])
            if file_path:
                pem_data_write = text_box.get('1.0', 'end-1c')
                with open(file_path, 'w') as file:
                    file.write(pem_data_write)
           

        key_generate_window = tk.Toplevel()
        key_generate_window.geometry("1200x700")
        key_generate_window.title("Generate Public Private Key Pair")

        # Bit label
        bits_label = tk.Label(key_generate_window, text="Number of Bits:")
        bits_label.pack()

        bits_entry = tk.Entry(key_generate_window)
        bits_entry.pack()

        # Generate button
        generate_button = tk.Button(key_generate_window, text="Generate", command=generate_keys_from_bits)
        generate_button.pack()

        # Left side - 
        public_frame = tk.Frame(key_generate_window)
        public_frame.pack(side=tk.LEFT, padx=10, pady=10)

        tk.Label(public_frame, text="Public Key(n, e)").pack()
        publickey_int_textbox = scrolledtext.ScrolledText(public_frame, height=10, width=60, wrap="word")
        publickey_int_textbox.pack(padx=10, pady=10)

        tk.Label(public_frame, text="Public key(PEM file)").pack()
        publickey_pem_textbox = scrolledtext.ScrolledText(public_frame, height=10, width=65, wrap="word")
        publickey_pem_textbox.pack(padx=10, pady=10)

        public_save_button = tk.Button(public_frame, text="Save File", command= lambda: save_file(publickey_pem_textbox))
        public_save_button.pack(pady=20)

        # Right side - 
        private_frame = tk.Frame(key_generate_window)
        private_frame.pack(side=tk.RIGHT, padx=10, pady=10)

        tk.Label(private_frame, text="Private Key(n, e, d, p, q)").pack()
        privatekey_int_textbox = scrolledtext.ScrolledText(private_frame, height=10, width=60, wrap="word")
        privatekey_int_textbox.pack(padx=10, pady=10)

        tk.Label(private_frame, text="Private Key(PEM file)").pack()
        privatekey_pem_textbox = scrolledtext.ScrolledText(private_frame, height=10, width=65)
        privatekey_pem_textbox.pack(padx=10, pady=10)

        private_save_button = tk.Button(private_frame, text="Save File", command= lambda: save_file(privatekey_pem_textbox))
        private_save_button.pack(pady=20)

        
        
        



    def rsa_encoder_window():
     
     
        def rsa_encoder():
            
            message = plaintext_entry.get('1.0', 'end-1c')
            
            if not message:
                return
            
            try:    
                key = eval(publickey_int_textbox.get('1.0','end-1c'))
        
                if not isinstance(key , tuple):
                    show_error_popup("Error: Enter Key in format (n, e)")
                    return

            except:
                try:
                    key = get_public_key_from_pem((publickey_pem_textbox.get('1.0', 'end-1c')).encode('utf-8'))
                    publickey_int_textbox.delete('1.0', 'end')
                    publickey_int_textbox.insert('1.0',f'#(n , e)\n{key}')
                except:
                    show_error_popup('Error: Invalid PEM file')
                    return
            
            try:
                encrypted_text = encrypt_msg(message, key)
                encrypted_textbox.delete('1.0', 'end')
                encrypted_textbox.insert('1.0', encrypted_text)

                save_to_history(encrypted_text, key, message, "RSA Encoding")
            except:
                show_error_popup("Error: Unable to decode due to error. Please try again!")
            


        def upload_pem_file(text_box):
            file_path = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem"), ("All Files", "*.*")])
            if file_path:
                with open(file_path, 'r') as file:
                    pem_data = file.read()
                    text_box.delete('1.0', tk.END)
                    text_box.insert(tk.END, pem_data)


        def save_cipher_file(text_box):

            file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("TXT Files", "*.txt"), ("All Files", "*.*")])
            if file_path:
                cipher_data_write = text_box.get('1.0', 'end-1c')
                with open(file_path, 'w') as file:
                    file.write(cipher_data_write)



        encoder_window = tk.Toplevel()
        encoder_window.geometry("1250x650")
        encoder_window.title("RSA Encoder")

        # Plaintext input
        plaintext_label = tk.Label(encoder_window, text="Enter Plaintext:")
        plaintext_label.pack()

        plaintext_entry = scrolledtext.ScrolledText(encoder_window, height=5, width=50, wrap=tk.WORD)
        plaintext_entry.pack()
        # Encrypted Text
        encrypted_text_frame = tk.Frame(encoder_window)
        encrypted_text_frame.pack(pady=10)

        tk.Label(encrypted_text_frame, text="Encrypted Text").pack()
        encrypted_textbox = scrolledtext.ScrolledText(encrypted_text_frame, height=5, width=50, wrap=tk.WORD)
        encrypted_textbox.pack(padx=10, pady=10)

        encrypt_msg_save_button = tk.Button(encrypted_text_frame, text="Save Cipher Text", command= lambda: save_cipher_file(encrypted_textbox))
        encrypt_msg_save_button.pack(pady=20)

        # Left side - Public Key (Integer)
        public_int_frame = tk.Frame(encoder_window)
        public_int_frame.pack(side=tk.LEFT, padx=10, pady=10)

        tk.Label(public_int_frame, text="Public Key (Integer)").pack()
        publickey_int_textbox = scrolledtext.ScrolledText(public_int_frame, height=13, width=65, wrap="word")
        publickey_int_textbox.pack(padx=10, pady=10)
        publickey_int_textbox.insert(tk.END, "Enter Your public Key as (n, e)")

        # Right side - Public Key (PEM)
        public_pem_frame = tk.Frame(encoder_window)
        public_pem_frame.pack(side=tk.RIGHT, padx=10, pady=10)

        tk.Label(public_pem_frame, text="Public Key (PEM file)").pack()
        publickey_pem_textbox = scrolledtext.ScrolledText(public_pem_frame, height=13, width=65, wrap="word")
        publickey_pem_textbox.pack(padx=10, pady=10)
        publickey_pem_textbox.insert(tk.END, "upload your public key PEM file")

        upload_button = tk.Button(public_pem_frame, text="Upload PEM File", command=lambda: upload_pem_file(publickey_pem_textbox))
        upload_button.pack(pady=10)


        # Encrypt button
        encrypt_button = tk.Button(encoder_window, text="Encrypt", command=rsa_encoder)
        encrypt_button.pack()        
    



    def rsa_decoder_window():
        def rsa_decoder():
            
            message = (ciphertext_entry.get('1.0', 'end-1c'))
            if not message:
                return
            
            try:
                message = int(message)
            except:
                show_error_popup("Error: cipher text must be a Integer")
                return
            
            
            try:    
                key = eval(privatekey_int_textbox.get('1.0','end-1c'))
        
                if not isinstance(key , tuple):
                    show_error_popup("Error: Enter Key in format (n, e, d, p, q)")
                    return

            
            except:
                try:
                    key = get_private_key_from_pem((privatekey_pem_textbox.get('1.0', 'end-1c')).encode('utf-8'))
                    privatekey_int_textbox.delete('1.0', 'end')
                    privatekey_int_textbox.insert('1.0',f'#(n , e, d, p, q)\n{key}')

                except:
                    show_error_popup('Error: Invalid PEM file')
                    return
            
            try:
                decrypted_text = decrypt_msg(message, key)
                decrypted_textbox.delete('1.0', 'end')
                decrypted_textbox.insert('1.0', decrypted_text)

                save_to_history(message, key, decrypted_text, "RSA")
            except:
                show_error_popup("Error: entered Cipher Text is not correct! Please check again")
            


        def upload_pem_file(text_box):
            file_path = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem"), ("All Files", "*.*")])
            if file_path:
                with open(file_path, 'r') as file:
                    pem_data = file.read()
                    text_box.delete('1.0', tk.END)
                    text_box.insert(tk.END, pem_data)

        def upload_cipher_file(text_box):
            file_path = filedialog.askopenfilename(filetypes=[("TXT Files", "*.txt"), ("All Files", "*.*")])
            if file_path:
                with open(file_path, 'r') as file:
                    cipher_text = file.read()
                    text_box.delete('1.0', tk.END)
                    text_box.insert(tk.END, cipher_text)


        decoder_window = tk.Toplevel()
        decoder_window.geometry("1250x650")
        decoder_window.title("RSA decoder")

        # Ciphertext input
        ciphertext_label = tk.Label(decoder_window, text="Enter Ciphertext:")
        ciphertext_label.pack()

        ciphertext_entry = scrolledtext.ScrolledText(decoder_window, height=5, width=50, wrap=tk.WORD)
        ciphertext_entry.pack()
                
        cipher_upload_button = tk.Button(decoder_window, text="Upload Cipher Text", command=lambda: upload_cipher_file(ciphertext_entry))
        cipher_upload_button.pack(pady=10)

        # decrypted Text
        decrypted_text_frame = tk.Frame(decoder_window)
        decrypted_text_frame.pack(pady=10)

        tk.Label(decrypted_text_frame, text="Decrypted Text").pack()
        decrypted_textbox = scrolledtext.ScrolledText(decrypted_text_frame, height=5, width=50, wrap=tk.WORD)
        decrypted_textbox.pack(padx=10, pady=10)

        # Left side - Private Key (Integer)
        private_int_frame = tk.Frame(decoder_window)
        private_int_frame.pack(side=tk.LEFT, padx=10, pady=10)

        tk.Label(private_int_frame, text="Private Key (Integer)").pack()
        privatekey_int_textbox = scrolledtext.ScrolledText(private_int_frame, height=13, width=65, wrap="word")
        privatekey_int_textbox.pack(padx=10, pady=10)
        privatekey_int_textbox.insert(tk.END, "Enter Your private Key as (n, e)")

        # Right side - Private Key (PEM)
        private_pem_frame = tk.Frame(decoder_window)
        private_pem_frame.pack(side=tk.RIGHT, padx=10, pady=10)

        tk.Label(private_pem_frame, text="Private Key (PEM file)").pack()
        privatekey_pem_textbox = scrolledtext.ScrolledText(private_pem_frame, height=13, width=65, wrap="word")
        privatekey_pem_textbox.pack(padx=10, pady=10)
        privatekey_pem_textbox.insert(tk.END, "upload your private key PEM file")

        upload_button = tk.Button(private_pem_frame, text="Upload PEM File", command=lambda: upload_pem_file(privatekey_pem_textbox))
        upload_button.pack(pady=10)


        # Encrypt button
        decrypt_button = tk.Button(decoder_window, text="Decrypt", command=rsa_decoder)
        decrypt_button.pack()
    
    
    
    
    
    rsa_window = tk.Toplevel(window)
    rsa_window.geometry("900x600")
    rsa_window.title("RSA Encytption Decryption Tool")

    title_label = tk.Label(rsa_window, text="Select any option to proceed: ", font=("Helvetica", 15))
    title_label.pack(side=tk.TOP, pady=20)

    # Create a style for larger buttons
    button_style = ttk.Style()
    button_style.configure("TButton", font=("Helvetica", 10), padding=10)

    # Create buttons
    button_options = ["Generate Public Private Key Pair", "Encrypt using key", "Decrypt using key"]

    for option in button_options:
        button = ttk.Button(rsa_window, text=option, style="TButton", command=lambda opt=option: button_clicked(opt))
        button.pack(side=tk.TOP, padx=20, pady=20, anchor='w')


def show_history():
    history_window = tk.Toplevel(window)
    history_window.geometry('800x600')  # Set the size of the window
    history_window.title("History")

    history_text_label = tk.Label(history_window, text="History Log:")
    history_text_label.pack()

    history_text = scrolledtext.ScrolledText(history_window, height=30, width=100, wrap=tk.WORD)
    history_text.pack(expand=True, fill="both")  # Expand to fill the available space
    
    with open('history.txt', 'r') as file:
        history_entries = file.read().split('\n\n\n')

        for entry in history_entries:
            lines = entry.split('\n')
            for line in lines:
                if line.startswith("Time:"):
                    history_text.insert(tk.END, line + "\n", "heading")
                else:
                    history_text.insert(tk.END, line + "\n")

            # Add separation between two time data entries
            history_text.insert(tk.END, "\n" + ("-" * 50) + "\n\n")

    # Configure tag for heading
    history_text.tag_configure("heading", foreground="blue", font="helvetica 10 bold")


'''main window'''

# Create the main window
window = tk.Tk()
window.title("CRYPTO_SYSTEM")

# Set window size
window.geometry("700x500")

title_label = tk.Label(window, text="Select any option to proceed: ", font=("Helvetica", 15))
title_label.pack(side=tk.TOP, pady=20)

# Create a style for larger buttons
button_style = ttk.Style()
button_style.configure("TButton", font=("Helvetica", 10), padding=10)

# Create buttons
button_options = ["Caesar Cipher", "Mono-Substitution Cipher", "Poly-Substitution Cipher", "RSA Encryption and Decryptyion", "History","Exit"]

for option in button_options:
    button = ttk.Button(window, text=option, style="TButton", command=lambda opt=option: button_clicked(opt))
    button.pack(side=tk.TOP, padx=20, pady=20, anchor='w')

# Run the main loop
window.mainloop()
