from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import tkinter
from tkinter import messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from rsa import random_prime, solve, isMillerRabinPassed
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64




HOST = '127.0.0.1'
PORT = 33000

var = False         #true if DHKE in process
dhke_var_a_b = False
dhke = []   #all user with whom dhke has been completed
all = []    #all active users in server
secret_key_list = {}  # user:secret_key

p_g = (0, 0)
secret_prime = 0
public_prime_A = 0
public_prime_B = 0
usrname = (None, None)  #(role during key exchange i.e. initiator or receivor, actual username)
other_user = ''         #with whom key is exchanged
auto_generate = False   #variable to know if primes are entered manually or generated automatically


dhke_popup = None
dhke_p_entry = None
dhke_g_entry = None
dhke_secret_entry = None


def update(all):
    global dhke
    for name in dhke:
        if name not in all:
            dhke.remove(name)




"""Here messages are transffered using header to ensure separation between two different message"""

def send_message(message, client_socket):
    message_length = str(len(message)).zfill(10)
    client_socket.send(message_length.encode('utf-8') + message.encode('utf-8'))


def receive_message(client_socket):
    message_prefix = client_socket.recv(10).decode('utf-8')
    if not message_prefix:
        return None  

    try:
        message_length = int(message_prefix)
    except ValueError:
        print("Invalid message length prefix")
        return None
    message = client_socket.recv(message_length).decode('utf-8')
    return message




"""Here is Encryption algorithm"""

def derive_key(key, salt=b'salt', length=32):   #to convert secret key to 256 bit size
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100000,  
        backend=default_backend()
    )
    return kdf.derive(key.to_bytes((key.bit_length() + 7) // 8, 'big'))


def encrypt(message, key):  #using AES algorithm to encrypt msg (256 bits key)
    key_bytes = derive_key(key)
    
    # Pad the message to a multiple of 16 bytes (AES block size)
    padded_message = message + b'\0' * (16 - len(message) % 16)

    # Create an AES cipher with the provided key and AES-CFB mode
    cipher = Cipher(algorithms.AES(key_bytes), modes.CFB(b'\0' * 16), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encrypt the padded message
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    
    return ciphertext


def decrypt(ciphertext, key):
    key_bytes = derive_key(key)
    
    # Create an AES cipher with the provided key and AES-CFB mode
    cipher = Cipher(algorithms.AES(key_bytes), modes.CFB(b'\0' * 16), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

    return decrypted_message.rstrip(b'\0')  # Remove padding




'''Shows active users and users with secure channel'''

def show_user_lists():
    global all, dhke
    info_popup = tkinter.Toplevel(top)
    info_popup.title("Connected Users Info")

    def create_list_text(parent, label_text, data_list):
        label = tkinter.Label(parent, text=label_text)
        label.pack(pady=10)

        frame = tkinter.Frame(parent)
        frame.pack(pady=5)

        entry = tkinter.Text(frame, width=60, height=4)
        entry.pack(side=tkinter.LEFT)

        scrollbar = tkinter.Scrollbar(frame, command=entry.yview)
        entry['yscrollcommand'] = scrollbar.set
        scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)

        entry.insert("1.0", "\n".join(data_list))


    create_list_text(info_popup, "All Connected Users:", all)
    create_list_text(info_popup, "DHKE Connected Users:", dhke)




def dhke_status(user):
    return user in dhke


def user_exist(user):
    return user in all




def receive():
    global all, var, p_g, other_user, public_prime_A, public_prime_B, usrname

    while True:
        try:
            msg = receive_message(client_socket)
            if msg[:21] == ':::CONNECTED_USERS:::':
                all = eval(msg[21:])
                update(dhke)

            elif msg[-18:] == ':::DHKE_REQUEST:::':
                request_from = msg[:msg.find(' ')]
                other_user = request_from
                var = True
                usrname = ('Receivor', request_from)
                msg_list.insert(tkinter.END, f"[SERVER] : DHKE request received from {request_from}")
                dhke_initiator_popup()

            elif ':::(p, g):::' in msg:
                request_from2 = msg[:msg.find(' ')]
                msg = msg.replace(f'{request_from2} : :::(p, g):::', '')
                p_g = eval(msg)

            elif ':::PUBLIC_PRIME:::' in msg:
                msg = msg.replace(f'{other_user} : :::PUBLIC_PRIME:::', '')
                if usrname[0] == 'initiator':
                    public_prime_B = int(msg)
                else:
                    public_prime_A = int(msg)

            else:
                request_from2 = msg[:msg.find(' ')]

                if request_from2 in secret_key_list.keys():
                    msg = msg.replace(f'{request_from2} : ', '')
                    msg_decrypt_b64 = base64.b64decode(msg)
                    decoded_msg = decrypt(msg_decrypt_b64, secret_key_list[request_from2])
                    msg_list.insert(tkinter.END, f'{request_from2} : ' + decoded_msg.decode('utf-8'))
                else:
                    msg_list.insert(tkinter.END, '\n' + msg)

        except :
            break


def extract_username(message):
    if message[0] == '@' and ' ' in message:
        username = message[1:message.find(' ')]
        message = message[message.find(' ')+1:]
        return username, message

    elif message[0] == '@' and ' ' not in message:
        username = message[1:]
        message = ''
        return username, message
        
    else:
        return (False, message)





def dhke_initiator_popup():
    global dhke_popup, dhke_p_entry, dhke_g_entry, dhke_secret_entry, dhke_var_a_b, p_g, usrname, other_user

    dhke_popup = tkinter.Toplevel(top)
    dhke_popup.title("Diffie-Hellman Key Exchange Parameters")

    dhke_label = tkinter.Label(dhke_popup, text="Enter Diffie-Hellman Key Exchange Parameters:")
    dhke_label.pack(pady=10)

    # Function to ensure text wrapping
    def wrap_text(text_widget):
        text_widget.config(wrap=tkinter.WORD)

    dhke_p_label = tkinter.Label(dhke_popup, text="p:")
    dhke_p_label.pack()
    dhke_p_entry_frame = tkinter.Frame(dhke_popup)
    dhke_p_entry_frame.pack(pady=5)

    # Text widget for p
    dhke_p_entry = tkinter.Text(dhke_p_entry_frame, width=60, height=4)  # Increase the size of the text box
    dhke_p_entry.pack(side=tkinter.LEFT)

    # Scrollbar for p
    dhke_p_scrollbar_y = tkinter.Scrollbar(dhke_p_entry_frame, command=dhke_p_entry.yview)
    dhke_p_entry['yscrollcommand'] = dhke_p_scrollbar_y.set
    dhke_p_scrollbar_y.pack(side=tkinter.RIGHT, fill=tkinter.Y)

    # Wrap text in the text widget
    wrap_text(dhke_p_entry)

    dhke_g_label = tkinter.Label(dhke_popup, text="g:")
    dhke_g_label.pack()
    dhke_g_entry_frame = tkinter.Frame(dhke_popup)
    dhke_g_entry_frame.pack(pady=5)

    # Text widget for g
    dhke_g_entry = tkinter.Text(dhke_g_entry_frame, width=60, height=4)  # Increase the size of the text box
    dhke_g_entry.pack(side=tkinter.LEFT)

    # Scrollbar for g
    dhke_g_scrollbar_y = tkinter.Scrollbar(dhke_g_entry_frame, command=dhke_g_entry.yview)
    dhke_g_entry['yscrollcommand'] = dhke_g_scrollbar_y.set
    dhke_g_scrollbar_y.pack(side=tkinter.RIGHT, fill=tkinter.Y)

    # Wrap text in the text widget
    wrap_text(dhke_g_entry)

    dhke_secret_label = tkinter.Label(dhke_popup, text="Secret Prime:")
    dhke_secret_label.pack()
    dhke_secret_entry_frame = tkinter.Frame(dhke_popup)
    dhke_secret_entry_frame.pack(pady=10)

    # Text widget for secret prime
    dhke_secret_entry = tkinter.Text(dhke_secret_entry_frame, width=60, height=4)  # Increase the size of the text box
    dhke_secret_entry.pack(side=tkinter.LEFT)

    # Scrollbar for secret prime
    dhke_secret_scrollbar_y = tkinter.Scrollbar(dhke_secret_entry_frame, command=dhke_secret_entry.yview)
    dhke_secret_entry['yscrollcommand'] = dhke_secret_scrollbar_y.set
    dhke_secret_scrollbar_y.pack(side=tkinter.RIGHT, fill=tkinter.Y)

    # Wrap text in the text widget
    wrap_text(dhke_secret_entry)
    
    generate_button = tkinter.Button(dhke_popup, text="Auto-Generate", command = generate_p_g_private_key)
    generate_button.pack()



    dhke_button = tkinter.Button(dhke_popup, text="Submit", command=lambda: submit_dhke_parameters(
        dhke_p_entry.get("1.0", tkinter.END).strip(),
        dhke_g_entry.get("1.0", tkinter.END).strip(),
        dhke_secret_entry.get("1.0", tkinter.END).strip()))
    
    dhke_button.pack(pady=10)



def show_error_popup(error_message):
    messagebox.showerror("Error", error_message)
    
    


def generate_p_g_private_key():
    global dhke_p_entry, dhke_g_entry, dhke_secret_entry, auto_generate

    auto_generate = True
    dhke_p_entry.delete("1.0", tkinter.END)
    dhke_g_entry.delete("1.0", tkinter.END)
    dhke_secret_entry.delete("1.0", tkinter.END)
    dhke_p_entry.insert(tkinter.END,str(random_prime(256)))
    dhke_g_entry.insert(tkinter.END,random_prime(256))
    dhke_secret_entry.insert(tkinter.END,random_prime(256))


def check_valid_input(p_val, g_val, secret_prime_val):
    is_p_prime = isMillerRabinPassed(p_val)
    is_g_prime = isMillerRabinPassed(g_val)
    is_secret_prime = isMillerRabinPassed(secret_prime_val)

    return is_p_prime and is_g_prime and is_secret_prime 
       




def submit_dhke_parameters(p_val, g_val, secret_prime_val):

    global dhke_var_a_b, p_g, usrname, other_user, secret_prime, auto_generate

    if check_valid_input(int(p_val), int(g_val), int(secret_prime_val)) == False:
        show_error_popup("Some values passed are not prime")
        dhke_p_entry.delete("1.0", tkinter.END)
        dhke_g_entry.delete("1.0", tkinter.END)
        dhke_secret_entry.delete("1.0", tkinter.END)
        dhke_popup.destroy()
        p_g = (0, 0)
        secret_prime = 0
        
        dhke_initiator_popup()
    else:    
        my_p_g = (int(p_val), int(g_val))
        secret_prime = int(secret_prime_val)
        
        msg = f'@{other_user} ' + ':::(p, g):::' + str(my_p_g)
        send_message(msg, client_socket)
        
        while True:
            if p_g != (0, 0):
                break

        dhke_popup.destroy()
        
        if auto_generate == True:
            if usrname[0] == 'initiator':
                p_g = my_p_g

            else:
                my_p_g = p_g
                
            auto_generate = False
        if tuple(p_g) == tuple(my_p_g) :

            msg_list.insert(tkinter.END, f'Both parties agreed Upon: ')
            msg_list.insert(tkinter.END, f'p = {p_g[0]}')
            msg_list.insert(tkinter.END, f'g = {p_g[1]}')
            msg_list.insert(tkinter.END, f'Your secret prime number is: {secret_prime} ')
            dhke_var_a_b = True
            calculate_public_prime()


        else:
            p_g = (0, 0)
            secret_prime = 0
            show_error_popup("Both Parties provided different values of p and g")
            dhke_initiator_popup()


def calculate_public_prime():
    global public_prime_A, public_prime_B, usrname, other_user, secret_prime,dhke,secret_key_list,p_g,var_a_b
    if usrname[0] == 'initiator':

            public_prime_A = solve(p_g[1], secret_prime, p_g[0])
            msg_list.insert(tkinter.END, f'Public Prime(A): {public_prime_A}')
            send_message(f'@{other_user} :::PUBLIC_PRIME:::' + str(public_prime_A), client_socket)

            msg_list.insert(tkinter.END, "Waiting to recieve Public prime(B) from other user.....")
            while True:
                if public_prime_B != 0:
                    break
            msg_list.insert(tkinter.END, f'Public Prime(B): {public_prime_B}')


            secret_key = solve(public_prime_B, secret_prime, p_g[0])
            msg_list.insert(tkinter.END, f'Secret Key for encryption: {secret_key}')
            
            secret_key_list[other_user] = secret_key
            dhke.append(other_user)

            p_g = (0, 0)
            secret_prime = 0
            public_prime_A = 0
            public_prime_B = 0
            usrname = (None, None)
            other_user = ''
            var_a_b = False
        
    else:

            public_prime_B = solve(p_g[1], secret_prime, p_g[0])
            msg_list.insert(tkinter.END, f'Public Prime(B): {public_prime_B}')
            send_message(f'@{other_user} :::PUBLIC_PRIME:::' + str(public_prime_B),client_socket)
            
            
            msg_list.insert(tkinter.END, "Waiting to recieve Public prime(A) from other user.....")
            while True:
                if public_prime_A != 0:
                    break
            msg_list.insert(tkinter.END, f'Public Prime(A): {public_prime_A}')
            
            
            
            secret_key = solve(public_prime_A, secret_prime, p_g[0])
            msg_list.insert(tkinter.END, f'Secret Key for encryption: {secret_key}')

            secret_key_list[other_user] = secret_key
            dhke.append(other_user)

            p_g = (0, 0)
            secret_prime = 0
            public_prime_A = 0
            public_prime_B = 0
            usrname = (None, None)
            other_user = ''
            var_a_b = False







def send_button():
    global other_user, var, all, dhke, usrname
    
    msg = str(my_msg.get())
    my_msg.set("")
    
    if not msg:
        return
    
    (username, only_msg) = extract_username(msg)
    
    try:
        if only_msg == "{quit}":
            client_socket.close()
            top.quit()

        if username == False:  # No username specified, so broadcast to all
            send_message(msg, client_socket)
            msg_list.insert(tkinter.END, 'You: ' + msg)

        elif username == this_user:  # Sending to itself
            msg_list.insert(tkinter.END, 'You: ' + msg)

        else:
            if dhke_status(username):  # already dhke done
                
                msg_encrypted = encrypt(bytes(only_msg, 'utf-8'), secret_key_list[username])
                encoded_msg = base64.b64encode(msg_encrypted).decode('utf-8')

                msg = f'@{username} ' + encoded_msg
                msg_list.insert(tkinter.END,f'You : {only_msg}')
                send_message(msg, client_socket)

            else:
                if user_exist(username):  # perform dhke
                    var = True
                    msg_list.insert(tkinter.END, f'[SERVER] : Connection not secure with {username}, Initiating Diffie Hellman Key Exchange....')
                    send_message(f'@{username} :::DHKE_REQUEST:::', client_socket)
                    usrname = ("initiator", username)
                    other_user = username
                    dhke_initiator_popup()
                    

                else:  # if no such user exist raise error
                    msg_list.insert(tkinter.END, 'Server: No such user exist')

    except:

        client_socket.close()
        top.quit()


def on_closing(event=None):
    client_socket.close()
    top.quit()


# Function to connect to the server
def connect_to_server():
    
    username = username_entry.get()
    host = host_entry.get()
    ip = ip_entry.get()
    if not username or not host or not ip:
        return
    
    try:
        port = int(host)
    except:
        return

    if ' ' in username:
        show_error_popup("username cannot have space character")
        return
    
    ADDR = (ip, port)
    
    try:
        client_socket.connect(ADDR)
        send_message(username, client_socket)
        switch_to_chat_frame()
        
        # Start the receiving thread
        receive_thread = Thread(target=receive)
        receive_thread.start()
    except:
        show_error_popup('Server refused to connect')
    

def switch_to_chat_frame():
    # Hide the login frame
    login_frame.pack_forget()

    # Show the messages_frame (chat frame)
    messages_frame.pack()


# GUI setup
top = tkinter.Tk()
top.title("Chat On!")

# Chat Frame
messages_frame = tkinter.Frame(top)
my_msg = tkinter.StringVar()
my_msg.set("")
scrollbar = tkinter.Scrollbar(messages_frame)

msg_list = tkinter.Listbox(messages_frame, height=35, width=100, yscrollcommand=scrollbar.set, xscrollcommand=scrollbar.set)
scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
msg_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
msg_list.pack()
messages_frame.pack()

entry_field = tkinter.Entry(top, textvariable=my_msg, width=100)
entry_field.bind("<Return>", send_button)
entry_field.pack(ipady=30)

send_button = tkinter.Button(top, text="Send", command=send_button)
send_button.pack()

top.protocol("WM_DELETE_WINDOW", on_closing)

# Login Frame
login_frame = tkinter.Frame(top)

username_label = tkinter.Label(login_frame, text="Username:")
username_label.grid(row=0, column=0, padx=10, pady=5)
username_entry = tkinter.Entry(login_frame)
username_entry.insert(0, 'a')
username_entry.grid(row=0, column=1, padx=10, pady=5)

ip_label = tkinter.Label(login_frame, text="IP:")
ip_label.grid(row=1, column=0, padx=10, pady=5)
ip_entry = tkinter.Entry(login_frame, textvariable=HOST)
ip_entry.insert(0, '127.0.0.1')
ip_entry.grid(row=1, column=1, padx=10, pady=5)

host_label = tkinter.Label(login_frame, text="Host:")
host_label.grid(row=2, column=0, padx=10, pady=5)
host_entry = tkinter.Entry(login_frame, textvariable=PORT)
host_entry.insert(0, '33000')
host_entry.grid(row=2, column=1, padx=10, pady=5)

login_button = tkinter.Button(login_frame, text="Login", command=connect_to_server)
login_button.grid(row=3, columnspan=2, pady=10)

login_frame.pack()

show_users_button = tkinter.Button(top, text="Show Connected Users", command=show_user_lists)
show_users_button.pack()
# Socket part

BUFSIZ = 1024
ADDR = (HOST, PORT)

client_socket = socket(AF_INET, SOCK_STREAM)
this_user = username_entry.get()




tkinter.mainloop()
