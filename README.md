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
  - Enter key in format that it substitutes letter in order 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'. Additonaly use virtual Keyboard to keep track of Key.

3. **Encrypt Button:**
  - Click the "Encrypt" button to perform the  encryption.

4. **View Encrypted Text:**
  - The encrypted text will be displayed in the designated text box labeled "Encrypted Text."
     ![encrypt](https://github.com/rahulpatel0408/cryptosystems/assets/147559135/859e3b20-be5d-4e10-b47d-b663bc898a8a)

#### Decryption:

1. **Enter Cipher Text:**
  - Input the ciphertext you want to decrypt into the designated text box labeled "Encrypted Text."

2. **Enter Key :**
  - Enter key in format that it substitutes letter in order 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'. Additonaly use virtual Keyboard to keep track of Key. In case you want to generate key hit generate Key button.

3. **Decrypt Button:**
  - If you entered the key, click the "Decrypt" button to perform the Caesar Cipher decryption.

4. **View Decrypted Text:**
  - The decrypted text will be displayed in the designated text box labeled "Decrypted Text."
    ![decrypt](https://github.com/rahulpatel0408/cryptosystems/assets/147559135/5028967e-9cef-4871-beec-be2cbd45830a)

3.3. **Poly Substitution Cipher:**
- If you selected "Poly Substitution Cipher," follow these additional steps:

#### Encryption:

1. **Enter Text to Encrypt:**
  - Input the plaintext you want to encrypt into the designated text box labeled "Decrypted Text."

2. **Enter Key:**
  - Enter key. Remeber Key can only be alphabetic string not numbers or any special character.

3. **Encrypt Button:**
  - Click the "Encrypt" button to perform the  encryption.

4. **View Encrypted Text:**
  - The encrypted text will be displayed in the designated text box labeled "Encrypted Text."
    ![WhatsApp Image 2024-01-02 at 21 49 17_f27d22ec](https://github.com/rahulpatel0408/cryptosystems/assets/147559135/143cd4c4-6a7f-4fcf-83f1-7b3a6ec19d74)
     

#### Decryption:

1. **Enter Cipher Text:**
  - Input the ciphertext you want to decrypt into the designated text box labeled "Encrypted Text."

2. **Enter Key :**
  - Enter key. Remeber Key can only be alphabetic string not numbers or any special character.

3. **Decrypt Button:**
  - If you entered the key, click the "Decrypt" button to perform the Caesar Cipher decryption.

4. **View Decrypted Text:**
  - The decrypted text will be displayed in the designated text box labeled "Decrypted Text."
    ![WhatsApp Image 2024-01-02 at 21 49 54_394e2831](https://github.com/rahulpatel0408/cryptosystems/assets/147559135/0ee5f3f8-184b-49de-824f-ca651bd18c0e)



