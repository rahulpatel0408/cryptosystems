# CyberLabs Project

## Overview
The completion of the CyberLabs project is divided into two fundamental parts: a robust cryptosystem and the implementation of the Diffie-Hellman key exchange protocol. This project is hosted on GitHub, with two main files: `cryptosystem` and `Diffie_Hellman_key_exchange`.

### Cryptosystem Component
The cryptosystem segment incorporates three distinct cipher techniques, namely Caesar, Substitution, and RSA. Each of these techniques plays a vital role in securing sensitive information through various encryption methods. The inclusion of Caesar and Substitution ciphers offers private-key encryption options, while the RSA technique provides a public-key encryption method.

### Diffie-Hellman Key Exchange Based Chat Application
The second part of the project involves the implementation of the Diffie-Hellman key exchange protocol. This protocol operates within a client-server model, ensuring secure key exchange in an environment where the communication channel might be insecure. By employing this protocol, the project aims to establish a robust foundation for secure communication, contributing to the overall information security objectives.

## Repository Structure
The project is organized into two main files within the GitHub repository:
- `Cryptosystems/CryptoSystems/cryptosystem.py`: Contains the implementation of the cryptosystem with Caesar, Substitution, and RSA techniques.
- `Cryptosystems/Diffie Hellman Key Exchange`: Encompasses the implementation of the Diffie-Hellman key exchange protocol for secure communication.

# Part 1
## CryptoSystems
### Directory Structure
The Cryptosystem directory within the Git repository contains several files, each serving a specific function. The main script, named `Cryptosystem`, acts as the user interface, integrating all modules together. Additionally, there are several other files such as `caesar_decode`, `caesar_encode`, `mono_sub_encoder`, etc., each containing modules with specific functions.

### Main Script - Cryptosystem.py
The main script, `Cryptosystem.py`, is the core component of the Cryptosystem directory. It serves as the user interface and seamlessly integrates all the cipher modules together. The script is built using the `tkinter` library, providing a graphical user interface (GUI) for users to interact with the different encryption and decryption functionalities.

### Cipher Types Supported
The `Cryptosystem` script is capable of performing encryption and decryption for the following Cipher Types:

1. **Caesar Cipher:**
   - Handled by modules: `caesar_decode` and `caesar_encode`.

2. **Mono Substitution Cipher:**
   - Handled by modules: `monosub_encoder` and `monosub_decoder`.

3. **Poly Substitution Cipher:**
   - Handled by modules: `polysub_encoder` and `polysub_decoder`.

4. **RSA:**
   - Handled by modules: `rsa`.

## How to Use

To use the Cryptosystem script and explore its encryption and decryption functionalities, follow these steps:

1. **Run the Script:**
   - Locate the `cryptoSystem.py` file within the repository.

2. **Home Page:**
   - Upon running the script, a home page will appear in the GUI, presenting different options for encryption and decryption.
     ![main](https://github.com/rahulpatel0408/cryptosystems/assets/147559135/9a107dde-46a5-4cdc-befa-4b42d6ef7179)

3. **Select Cipher Type:**
   - Choose the desired cipher type from the available options. For example, you can select "Caesar Cipher," "Mono Substitution Cipher," "Poly Substitution Cipher," or "RSA."

   3.1. **Caesar Cipher:**
       - If you selected "Caesar Cipher," follow these additional steps:

     #### Encryption:

     1. **Enter Text to Encrypt:**
        - Input the plaintext you want to encrypt into the designated text box labeled "Decrypted Text."

     2. **Enter Shift Key:**
        - Specify the shift value (key) you want to use for encryption.

     3. **Encrypt Button:**
        - Click the "Encrypt" button to perform the Caesar Cipher encryption.

     4. **View Encrypted Text:**
        - The encrypted text will be displayed in the designated text box labeled "Encrypted Text."
          ![encryption r](https://github.com/rahulpatel0408/cryptosystems/assets/147559135/69dfffa4-4aef-43f3-a206-211f4c80637d)

     #### Decryption:

     1. **Enter Cipher Text:**
        - Input the ciphertext you want to decrypt into the designated text box labeled "Encrypted Text."

     2. **Enter Shift Key (Optional):**
        - If you have the shift value (key) used for encryption, enter it into the corresponding text box. Otherwise, proceed to step 3.

     3. **AutoSolve (Optional):**
        - If you do not have the key, you can use the "AutoSolve" button to attempt an automatic decryption by trying all possible shift values.

     4. **Decrypt Button:**
        - If you entered the key or used AutoSolve, click the "Decrypt" button to perform the Caesar Cipher decryption.

     5. **View Decrypted Text:**
        - The decrypted text will be displayed in the designated text box labeled "Decrypted Text."
          ![decryption](https://github.com/rahulpatel0408/cryptosystems/assets/147559135/3cbdb547-b0cc-47db-aede-1f0f240746a1)
          ![auto dec](https://github.com/rahulpatel0408/cryptosystems/assets/147559135/832da8f7-44ff-489b-9da7-4aab8ae47785)

   3.2. **Mono Substitution Cipher:**
       - If you selected "Mono Substitution Cipher," follow these additional steps:

     #### Encryption:

     1. **Enter Text to Encrypt:**
        - Input the plaintext you want to encrypt into the designated text box labeled "Decrypted Text."

     2. **Enter Key:**
        - Enter key in format that it substitutes letter in order 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'. Additionally, use the virtual Keyboard to keep track of Key.

     3. **Encrypt Button:**
        - Click the "Encrypt" button to perform the  encryption.

     4. **View Encrypted Text:**
        - The encrypted text will be displayed in the designated text box labeled "Encrypted Text."
          ![encrypt](https://github.com/rahulpatel0408/cryptosystems/assets/147559135/859e3b20-be5d-4e10-b47d-b663bc898a8a)

     #### Decryption:

     1. **Enter Cipher Text:**
        - Input the ciphertext you want to decrypt into the designated text box labeled "Encrypted Text."

     2. **Enter Key:**
        - Enter the key in format that it substitutes letter in order 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'. Additionally, use the virtual Keyboard to keep track of Key. In case you want to generate the key hit the generate Key button.

     3. **Decrypt Button:**
        - If you entered the key, click the "Decrypt" button to perform the Cipher decryption.

     4. **View Decrypted Text:**
        - The decrypted text will be displayed in the designated text box labeled "Decrypted Text."
          ![decrypt](https://github.com/rahulpatel0408/cryptosystems/assets/147559135/5028967e-9cef-4871-beec-be2cbd45830a)

   3.3. **Poly Substitution Cipher:**
       - If you selected "Poly Substitution Cipher," follow these additional steps:

     #### Encryption:

     1. **Enter Text to Encrypt:**
        - Input the plaintext you want to encrypt into the designated text box labeled "Decrypted Text."

     2. **Enter Key:**
        - Enter the key. Remember the key can only be an alphabetic string, not numbers or any special character.

     3. **Encrypt Button:**
        - Click the "Encrypt" button to perform the  encryption.

     4. **View Encrypted Text:**
        - The encrypted text will be displayed in the designated text box labeled "Encrypted Text."
          ![WhatsApp Image 2024-01-02 at 21 49 17_f27d22ec](https://github.com/rahulpatel0408/cryptosystems/assets/147559135/143cd4c4-6a7f-4fcf-83f1-7b3a6ec19d74)

     #### Decryption:

     1. **Enter Cipher Text:**
        - Input the ciphertext you want to decrypt into the designated text box labeled "Encrypted Text."

     2. **Enter Key:**
        - Enter the key. Remember the key can only be an alphabetic string, not numbers or any special character.

     3. **Decrypt Button:**
        - If you entered the key, click the "Decrypt" button to perform the Cipher decryption.

     4. **View Decrypted Text:**
        - The decrypted text will be displayed in the designated text box labeled "Decrypted Text."
          ![WhatsApp Image 2024-01-02 at 21 49 54_394e2831](https://github.com/rahulpatel0408/cryptosystems/assets/147559135/0ee5f3f8-184b-49de-824f-ca651bd18c0e)

   3.4. **RSA:**
       - If you selected "RSA," follow these additional steps:

     #### Generate Keys:

     1. **Enter Bits Size of Key:**
        - Remember to keep the bit size below 1200 Bits due to computational constraints. 1024 Bits is the ideal choice.

     2. **Save Key:**
        - Hit the Save file button to save Public and Private Keys for further use or note down integer values of the key.
          ![gen key](https://github.com/rahulpatel0408/cryptosystems/assets/147559135/49d88983-51bd-41c2-ab03-e8d06c0fede9)

     #### Encryption:

     1. **Enter Text to Encrypt:**
        - Input the plaintext you want to encrypt into the designated text box labeled "Input Text."

     2. **Enter Key:**
        - You can either upload the pem file you saved earlier or input integer values in the form (n, e).

     3. **Encrypt Button:**
        - Click the "Encrypt" button to perform the  encryption.

     4. **Save Cipher Text:**
        - Enter the Save Cipher Text button to save the file in the desired path
          ![encrypt](https://github.com/rahulpatel0408/cryptosystems/assets/147559135/fdda9533-bf52-4d44-a02e-3ea44544f1a7)

     #### Decryption:

     1. **Enter Cipher Text:**
        - Input the ciphertext you want to decrypt into the designated text box labeled "Encrypted Text."

     2. **Enter Key:**
        - You can either upload the pem file you saved earlier or input integer values in the form (n, e, d, p, q).

     3. **Decrypt Button:**
        - If you entered the key, click the "Decrypt" button to perform the Caesar Cipher decryption.
        - ![decrypt](https://github.com/rahulpatel0408/cryptosystems/assets/147559135/40bbb661-f73e-49da-aa75-4bd98660b7fb)

      3.4. **RSA:**
       - If you selected "RSA," follow these additional steps:

     #### Generate Keys:

     1. **Enter Bits Size of Key:**
        - Remember to keep the bit size below 1200 Bits due to computational constraints. 1024 Bits is the ideal choice.

     2. **Save Key:**
        - Hit the Save file button to save Public and Private Keys for further use or note down integer values of the key.
          ![gen key](https://github.com/rahulpatel0408/cryptosystems/assets/147559135/49d88983-51bd-41c2-ab03-e8d06c0fede9)

     #### Encryption:

     1. **Enter Text to Encrypt:**
        - Input the plaintext you want to encrypt into the designated text box labeled "Input Text."

     2. **Enter Key:**
        - You can either upload the pem file you saved earlier or input integer values in the form (n, e).

     3. **Encrypt Button:**
        - Click the "Encrypt" button to perform the  encryption.

     4. **Save Cipher Text:**
        - Enter the Save Cipher Text button to save the file in the desired path
          ![encrypt](https://github.com/rahulpatel0408/cryptosystems/assets/147559135/fdda9533-bf52-4d44-a02e-3ea44544f1a7)

     #### Decryption:

     1. **Enter Cipher Text:**
        - Input the ciphertext you want to decrypt into the designated text box labeled "Encrypted Text."

     2. **Enter Key:**
        - You can either upload the pem file you saved earlier or input integer values in the form (n, e, d, p, q).

     3. **Decrypt Button:**
        - If you entered the key, click the "Decrypt" button to perform the Caesar Cipher decryption.
        - ![decrypt](https://github.com/rahulpatel0408/cryptosystems/assets/147559135/40bbb661-f73e-49da-aa75-4bd98660b7fb)
   
   3.5. **History:**
       -  This features keeps record of all previous cipher encryption and decryption with time stamp.
       - ![image](https://github.com/rahulpatel0408/cryptosystems/assets/147559135/e04adf0e-c2b2-405e-ab54-b105bb6a2f16)



# Part 2
## Diffie-Hellman Key Exchange Based Chat Application

### Directory Structure
The 'Diffie Hellman Key Exchange' directory within the Git repository contains 3 files: `client.py`, `server.py`, and `rsa.py`. The scripts, named `server.py` and `client.py`, are main files that perform Diffie-Hellman key exchange. Additionally, there is an `rsa.py` file that contains functions used in the other two files.

### server.py
- The server initializes a socket and binds it to a specific address (`HOST` and `PORT`).
- It listens for incoming connections and spawns a new thread (`ACCEPT_THREAD`) for each client that connects.
- Each client is identified by a unique username, and the server maintains a dictionary (`clients`) to keep track of connected clients.
- The server handles each client in a separate thread (`handle_client`). It receives messages from clients, broadcasts them to all other clients, and handles direct messages.
- The server can listen to any messages sent over the channel and is, therefore, considered an insecure channel.

### client.py
- The client initializes a socket and connects to the server using the specified `HOST` and `PORT`.
- The client provides a unique username for identification.
- It supports a graphical user interface (GUI) using tkinter, where users can send messages to all clients or initiate direct messages.
- The client handles key exchange using Diffie-Hellman. It checks for username availability, sends and receives encrypted messages, and updates the list of connected users.
- The client has a separate thread (`receive_thread`) for receiving messages from the server.

## How to Use:
### Server Login
- To access the server, use the following credentials:
  - IP: `127.0.0.1`
  - Host: `33000`
![WhatsApp Image 2024-01-02 at 23 11 30_ce72dac0](https://github.com/rahulpatel0408/cryptosystems/assets/147559135/e9221b4e-1fa1-4d43-a07e-4c4c41ac4975)

### User Authentication
- Enter a valid username to log in. A valid username must be a single word with no spaces and should not be in use by another user on the server.
   
### Sending Messages
- To send a message to everyone, type your message and click the "Send" button.
- To send a message to a specific user, use the format `@username` at the beginning of your message.

### Diffie-Hellman Key Exchange
- When initiating a direct message with a particular user for the first time, Diffie-Hellman key exchange will be automatically initiated.
- Enter the values for `p`, `g`, and your secret key when prompted. Alternatively, you can use the "generate" option to let the script calculate the secret key.
- The secret key is then converted to a 256-bit size for secure communication.
![WhatsApp Image 2024-01-02 at 23 14 35_a0bb4166](https://github.com/rahulpatel0408/cryptosystems/assets/147559135/78f8702f-b6e3-420c-be12-e98f4dde48ae)
![WhatsApp Image 2024-01-02 at 23 15 01_ac32ee20](https://github.com/rahulpatel0408/cryptosystems/assets/147559135/9c9a68ce-26ad-4cfd-88a9-c68a696408b5)

### Encrypted Messaging
- Once the Diffie-Hellman key exchange is completed, messages sent through the server are encrypted.
- Only the intended recipient can decrypt and read the messages.
![WhatsApp Image 2024-01-02 at 23 18 19_5931838f](https://github.com/rahulpatel0408/cryptosystems/assets/147559135/6838be75-d762-47b4-aa49-db145477645e)

