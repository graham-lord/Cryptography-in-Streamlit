# install streamlit: pip install streamlit
# run: stramlit run app.py
import rsa
import streamlit as st
import hashlib
import base64
from cryptography.fernet import Fernet 

# Define function for symmetric encryption
def symmetric_encryption():
    st.write("## Fernet Algorithm")
    st.write("### Discussion")
    st.write("The Fernet algorithm is a symmetric encryption algorithm used to securely encrypt and decrypt data. It belongs to a class of algorithms known as symmetric key cryptography, which means that the same key is used for both encryption and decryption. In the Fernet algorithm, the key used for encryption and decryption is a 32-byte URL-safe base64-encoded string. This key must be kept secret because anyone with the key can decrypt the encrypted data.")
    st.write("### Application")
    def generate_key():
        return Fernet.generate_key()

    def encrypt_message(message, key):
        fernet = Fernet(key)
        encrypted_message = fernet.encrypt(message.encode())
        return encrypted_message.decode()

    def cipher():
        st.write("## Message Encryption")

        # Input field for message
        message = st.text_input("Enter your message:")

        # Input field for key or generate key button
        key = st.text_input("Enter your encryption key (or leave empty to generate a key):")
        if not key:
            if st.button("Generate Key"):
                key = generate_key().decode()
                st.success("Generated Key: " + key)

        # Encrypt button
        if st.button("Encrypt"):
            if message and key:
                encrypted_message = encrypt_message(message, key)
                st.success("Encrypted message: " + encrypted_message)
            else:
                st.warning("Please enter both a message and a key.")

    def decrypt_message(encrypted_message, key):
        fernet = Fernet(key)
        decrypted_message = fernet.decrypt(encrypted_message.encode())
        return decrypted_message.decode()

    def decipher():
        st.write("## Message Decryption")

        # Input field for encrypted message
        encrypted_message = st.text_input("Enter the encrypted message:")

        # Input field for secret key
        key = st.text_input("Enter your secret key:")

        # Decrypt button
        if st.button("Decrypt"):
            if encrypted_message and key:
                decrypted_message = decrypt_message(encrypted_message, key)
                st.success("Decrypted message: " + decrypted_message)
            else:
                st.warning("Please enter both the encrypted message and the secret key.")

    tab1, tab2 = st.tabs(["Encrypt", "Decrypt"])
    with tab1: 
        cipher()
    with tab2:
        decipher()
# Define function for asymmetric encryption
def asymmetric_encryption():
    st.write("## RSA Algorithm")
    st.write("### Discussion:")
    st.write("The RSA algorithm is a popular asymmetric encryption algorithm that relies on the properties of prime numbers. It involves the use of two different keys: a public key and a private key. The security of the RSA algorithm is based on the mathematical difficulty of factoring large composite numbers. The private key exponent (d) is derived from the modulus (N) and another factor, which is kept secret. It is computationally infeasible to determine the private key (and therefore decrypt the message) if the factors of the modulus are unknown.")
    st.write("### Application:")

    def encrypt_message(message, key_str):
        # Load the RSA key from string
        key = rsa.PublicKey.load_pkcs1(key_str.encode('utf-8'))

        # Encrypt the message using the RSA key
        encrypted_message = rsa.encrypt(message.encode('utf-8'), key)

        return encrypted_message

    def generate_rsa_keys():
        # Generate RSA key pair
        public_key, private_key = rsa.newkeys(515)

        # Convert keys to string format
        public_key_str = public_key.save_pkcs1().decode('utf-8')
        private_key_str = private_key.save_pkcs1().decode('utf-8')

        return public_key_str, private_key_str

    public_key, private_key = generate_rsa_keys()

    def cipher():
        if st.button("Generate Keys"):
            st.text_area("Public Key", public_key, height=200)
            st.text_area("Private Key", private_key, height=200)

        message = st.text_input("Enter message to be encrypted: ", "HELLO WORLD!!")
        key = st.text_area("Enter your public key for encryption: ")

        if st.button("Encrypt with RSA"):
            if message and key:
                encrypted_message = encrypt_message(message, key)
                st.success("Encrypted message: " + encrypted_message.hex())
            else:
                st.warning("Please enter both a message and a key.")

    def decrypt_message(encrypted_message, key_str):
        # Load the RSA key from string
        key = rsa.PrivateKey.load_pkcs1(key_str.encode('utf-8'))

        # Decrypt the message using the RSA key
        decrypted_message = rsa.decrypt(encrypted_message, key)

        return decrypted_message.decode('utf-8')

    def decipher():
        encrypted_message = st.text_area("Enter the encrypted message: ")
        private_key = st.text_area("Enter your private key for decryption: ", height=200)

        if st.button("Decrypt with RSA"):
            if encrypted_message and private_key:
                encrypted_message_bytes = bytes.fromhex(encrypted_message)
                decrypted_message = decrypt_message(encrypted_message_bytes, private_key)
                st.success("Decrypted message: " + decrypted_message)
            else:
                st.warning("Please enter both an encrypted message and a private key.")
    tab1, tab2 = st.tabs(["Encrypt", "Decrypt"])
    with tab1: 
        cipher()
    with tab2:
        decipher()

# Define function for hashing
def hashing():
    st.write("## MD5(Message Digest Algorithm)5")
    st.write("### Discussion:")
    st.write("MD5 (Message Digest Algorithm 5) is a widely used cryptographic hash function. Its purpose is to take an input (such as a message, file, or data) and produce a fixed-size output called a hash or digest. The MD5 algorithm is designed to be fast and efficient, generating a 128-bit hash value.")
    st.write("### Application:")

    def calculate_md5(message):
        md5_hash = hashlib.md5()
        md5_hash.update(message.encode('utf-8'))
        return md5_hash.hexdigest()
    
    message = st.text_input("Enter message to hash: ", "Hello World!!")
    if st.button("Hash"):
        md5_hash = calculate_md5(message)
        st.write("MD5 Hash: ", md5_hash)
    
    pass

# Main Streamlit app
def main():
    st.title("Cryptographic Application")
    st.write("## Introduction:")
    st.write("Cryptography plays a vital role in maintaining the safety and accuracy of information on the Internet. It offers various methods for ensuring security, including symmetric encryption, asymmetric encryption, and hashing.")
    st.write("- Symmetric Cryptography involves using the same key for both encrypting and decrypting data. This approach is particularly advantageous when dealing with large volumes of data due to its efficiency and speed.")
    st.write("- Asymmetric Cryptography, on the other hand, utilizes a public key to encrypt the data and a private key to decrypt it. While it provides stronger security measures, it tends to be slower compared to symmetric encryption due to its time complexity.")
    st.write("- Hashing is a technique that generates a fixed-size output using a one-way function. It is commonly employed to validate the integrity of data, ensuring that it hasn't been tampered with.")
    st.write("## Project Objectives:")
    st.write("1. Implement Fernet, RSA, and MD5 in the system.")
    st.write("2. Create an intuitive system interface utilizing Streamlit that enables users to effortlessly encrypt, decrypt, and generate hashes for messages.")
    st.write("3. Illustrate the application and execution of these cryptographic methods, emphasizing their advantages and constraints.")
    # Create tabs
    tab1, tab2, tab3 = st.tabs(["Symmetric Cryptography", "Asymmetric Cryptography", "Hashing"])
    with tab1:
        symmetric_encryption()
    with tab2:
        asymmetric_encryption()
    with tab3:
        hashing()



    st.markdown(
        """
        <style>
        .footer {
            position: fixed;
            left: 0;
            bottom: 0;
            width: 100%;
            background-color: #f8f9fa;
            padding: 10px;
            text-align: center;
        }
        </style>
        """
    , unsafe_allow_html=True)

    # You can customize the footer content here
   # Set the footer text
footer_text = """
<div style="text-align: center;">
    <p>Submitted by:</p>
    <h3>Arnante, Diana</h3>
    <h3>Besa, Kelsey Eunice</h3>
    <h3>Estallo, Joshua</h3>
    <p>BSCS 3A</p>
</div>
"""

# Add the footer to the sidebar
st.sidebar.markdown(footer_text, unsafe_allow_html=True)

# Rest of your Streamlit app code...

if __name__ == "__main__":
    main()