import os
# The `import subprocess` statement is importing the `subprocess` module, which allows you to spawn
# new processes, connect to their input/output/error pipes, and obtain their return codes. It provides
# a way to run system commands and interact with the operating system from within a Python script.
import subprocess
# The line `import tkinter as tk` is importing the `tkinter` module and assigning it the alias `tk`.
# This allows you to use the `tkinter` module's functions, classes, and objects by prefixing them with
# `tk.`. For example, `tk.Tk()` creates a new instance of the `Tk` class, which represents the main
# window of a Tkinter application.
import tkinter as tk
from tkinter import ttk
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def generate_rsa_keys():
    try:
        # Check if files already exist and delete them
        delete_files(["privkey-A.pem", "privkey-B.pem", "pubkey-A.pem", "pubkey-B.pem"])

# The code `private_key_a = rsa.generate_private_key(public_exponent=65537, key_size=2048)` is
# generating a private key using the RSA algorithm.
        private_key_a = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

# The code `private_key_b = rsa.generate_private_key(public_exponent=65537, key_size=2048)` is
# generating a private key using the RSA algorithm. The `generate_private_key` function is called from
# the `rsa` module of the `cryptography.hazmat.primitives.asymmetric` package. It takes two arguments:
# `public_exponent` and `key_size`.
        private_key_b = rsa.generate_private_key(
            # The `public_exponent` parameter in the `rsa.generate_private_key()` function is used to
            # specify the public exponent value for the generated RSA private key. The public exponent
            # is a positive integer that is relatively prime to the totient of the modulus. In RSA,
            # the public exponent is typically set to a fixed value, such as 65537, which is a
            # commonly used value for its efficiency and security properties.
            public_exponent=65537,
            # The `key_size` parameter is used to specify the size of the generated RSA private key.
            # In this code, it is set to 2048, which means that the generated private key will have a
            # size of 2048 bits. The key size determines the strength and security of the RSA
            # encryption algorithm. A larger key size generally provides stronger security but
            # requires more computational resources for encryption and decryption operations.
            key_size=2048
        )

        # Save private keys to files
        save_private_key(private_key_a, "privkey-A.pem")
        save_private_key(private_key_b, "privkey-B.pem")

        # Save public keys to files
        save_public_key(private_key_a.public_key(), "pubkey-A.pem")
        save_public_key(private_key_b.public_key(), "pubkey-B.pem")

        # Display success message
        result_label.config(text="RSA keys generated and saved.")

    except Exception as e:
        result_label.config(text=f"Error: {str(e)}")

def generate_aes_key():
    """
    The function generates a 256-bit AES key using the os.urandom() function.
    :return: a randomly generated 256-bit AES key.
    """
    return os.urandom(32)  # Generate a 256-bit AES key

def encrypt_decrypt():
    try:
        # Get the private key from file
        private_key_b = load_private_key("privkey-B.pem")

        if private_key_b is None:
            result_label.config(text="Private key B not found.")
            return

        # Generate AES key
        aes_key = generate_aes_key()
        cipher = Cipher(algorithms.AES(aes_key), modes.ECB())

        # Get the message from the user
        message = message_entry.get()

        if not message:
            result_label.config(text="Please enter a message.")
            return

        # Encrypt the message using AES with PKCS7 padding
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message.encode()) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Save the encrypted data to a file
        save_data_to_file(encrypted_data, "encrypted_data.bin")

        # Save the AES key to a file
        save_data_to_file(aes_key, "aes_key.bin")

        # Display success message
        result_label.config(text="Message encrypted and saved.")

    except Exception as e:
        result_label.config(text=f"Error: {str(e)}")

def compare_with_openssl():
    try:
        # Load the encrypted data from the file
        encrypted_data = load_data_from_file("encrypted_data.bin")

        if encrypted_data is None:
            result_label.config(text="Encrypted data not found.")
            return

        # Load the AES key from the file
        aes_key = load_data_from_file("aes_key.bin")

        if aes_key is None:
            result_label.config(text="AES key not found.")
            return

        # Run OpenSSL command to decrypt the data
        openssl_command = f"openssl enc -d -aes-256-ecb -nopad -K {aes_key.hex()} -in encrypted_data.bin -out decrypted_data.txt"
        subprocess.run(openssl_command, shell=True)

        # Read the decrypted data from the file
        with open("decrypted_data.txt", "rb") as f:
            decrypted_data = f.read()

        # Remove PKCS7 padding
        # The line `unpadder = padding.PKCS7(128).unpadder()` is creating an instance of the `PKCS7`
        # padding object with a block size of 128 bits. The `PKCS7` padding scheme is a commonly used
        # padding scheme in cryptography that adds padding bytes to the end of a message to ensure
        # that the message length is a multiple of the block size.
        unpadder = padding.PKCS7(128).unpadder()
        # The line `unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()` is
        # performing the unpadding operation on the decrypted data.
        unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

        # Decode the decrypted and unpadded data
        decrypted_message = unpadded_data.decode()

        # Display the OpenSSL decryption result
        result_label.config(text=f"OpenSSL Decryption Result:\n{decrypted_message}")

    except Exception as e:
        result_label.config(text=f"Error: {str(e)}")

def delete_files(file_list):
    """
    The function `delete_files` takes a list of file paths as input and deletes each file if it exists.
    
    :param file_list: The parameter `file_list` is a list of file paths
    """
    for file in file_list:
        if os.path.exists(file):
            os.remove(file)

def save_private_key(private_key, filename):
    """
    The function saves a private key to a file in PEM format without encryption.
    
    :param private_key: The private key object that you want to save to a file
    :param filename: The `filename` parameter is a string that specifies the name of the file where the
    private key will be saved
    """
    with open(filename, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

def save_public_key(public_key, filename):
    """
    The function saves a public key to a file in PEM format.
    
    :param public_key: The `public_key` parameter is an object that represents a public key. It is
    typically generated using a cryptographic library or algorithm
    :param filename: The `filename` parameter is a string that represents the name of the file where the
    public key will be saved. It should include the file extension, such as ".pem" or ".pub"
    """
    with open(filename, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_private_key(filename):
    """
    The function `load_private_key` loads a private key from a file in PEM format and returns it, or
    returns `None` if an error occurs.
    
    :param filename: The filename parameter is a string that represents the name or path of the file
    containing the private key
    :return: the private key loaded from the specified file. If an exception occurs during the loading
    process, it will return None.
    """
    try:
        with open(filename, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
            return private_key
    except Exception as e:
        return None

def save_data_to_file(data, filename):
    """
    The function saves data to a file.
    
    :param data: The data parameter is the content that you want to save to the file. It can be any type
    of data, such as a string, a list, or a dictionary
    :param filename: The filename parameter is a string that represents the name of the file where the
    data will be saved
    """
    with open(filename, "wb") as f:
        f.write(data)

def load_data_from_file(filename):
    try:
        with open(filename, "rb") as f:
            data = f.read()
            return data
    except Exception as e:
        return None

# Create the GUI
window = tk.Tk()
window.title("Secret Key Exchange Protocol")
window.geometry("370x400")

# Tab control
tab_control = tk.ttk.Notebook(window)

# Encrypt/Decrypt tab
encrypt_decrypt_tab = tk.Frame(tab_control)
tab_control.add(encrypt_decrypt_tab, text='Encrypt/Decrypt')

generate_keys_button = tk.Button(encrypt_decrypt_tab, text="Generate RSA Keys", command=generate_rsa_keys)
generate_keys_button.pack(pady=10)

message_label = tk.Label(encrypt_decrypt_tab, text="Enter Message:")
message_label.pack()

message_entry = tk.Entry(encrypt_decrypt_tab)
message_entry.pack()

encrypt_decrypt_button = tk.Button(encrypt_decrypt_tab, text="Encrypt and Save", command=encrypt_decrypt)
encrypt_decrypt_button.pack(pady=10)

compare_openssl_button = tk.Button(encrypt_decrypt_tab, text="Compare with OpenSSL", command=compare_with_openssl)
compare_openssl_button.pack(pady=10)

result_label = tk.Label(encrypt_decrypt_tab, text="")
result_label.pack(pady=10)

# About tab
about_tab = tk.Frame(tab_control)
tab_control.add(about_tab, text='About')

about_text = """
Group Members:
WAN MOHAMAD IRFAN BIN WAN RASHID - 1201302189
MUHAMAD IRSYAD BIN MAT YAAKOB - 1201302664
MUHAMMAD SAFUAN BIN HASRAM - 1161200955
KHAIRUL IMRAN BIN MUSTAPHA - 1161201946
"""

about_label = tk.Label(about_tab, text=about_text)
about_label.pack(pady=10)

# Pack the tab control
tab_control.pack(expand=1, fill='both')

window.mainloop()

