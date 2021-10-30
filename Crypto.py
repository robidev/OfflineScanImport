'''-------------------------------------------------------------------------------
Name:           Crypto.py
Date:           22/10/2021
Purpose:        perform crypto functions

Author:         Robin Massink
-------------------------------------------------------------------------------
Requirements:
   provide public and private keys
   you also have to make sure the 'cryptography' module is installed on your system

'''
import os
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature

class Crypto(object):
    """
    Class to handle crypto calls.
    """
    # Initializer / Instance Attributes
    def __init__(self, encrypt_public_key_filename: str, decrypt_private_key_filename: str, decrypt_pem_password: bytes):
        self.public_key_filename = encrypt_public_key_filename
        self.private_key_filename = decrypt_private_key_filename
        self.pem_password = decrypt_pem_password
        

    def encrypt_file(self, filename: str, output_filename: str) -> int:

        secret = None
        with open(filename, "rb") as secret_file:
            secret = secret_file.read()
        self.encrypt_data_to_file(secret, output_filename)
        return len(secret)


    def encrypt_data_to_file(self, secret: bytes, output_filename: str):
        key = os.urandom(32)
        iv = os.urandom(16)
        
        # encrypt symetric key with public key
        encoded_data = key + iv
        public_key = None
        with open(self.public_key_filename, "rb") as pub_key_file:
            public_key  = serialization.load_pem_public_key( pub_key_file.read(), backend=default_backend())
        ct_key = public_key.encrypt( encoded_data, padding=padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None,), )
          
        # encrypt file symetric with key and IV
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # pad until block length
        block_length = 16
        secret_length = len(secret)
        length_with_padding = ( secret_length + (block_length - secret_length) % block_length )
        secret_padded = secret.ljust(length_with_padding, b"\0")
        
        # encrypt the file-data
        ct = encryptor.update(secret_padded) + encryptor.finalize()

        # write the encrypted file and symetric key
        with open(output_filename + ".bin", "wb") as crypted_msg:
            crypted_msg.write(ct)
        with open(output_filename + ".key", "wb") as crypted_key:
            crypted_key.write(ct_key)


    def decrypt_file(self, filename: str, length: int, ct_key_filename: str, result_filename: str): 
        data = self.decrypt_file_to_data(filename, length, ct_key_filename)
        # write decrypted file
        with open(result_filename, "wb") as result:
            result.write(data)


    def decrypt_file_to_data(self, filename: str, length: int, ct_key_filename: str) -> bytes: 
        ct_key = None
        with open(ct_key_filename, "rb") as crypted_key_r:
            ct_key = crypted_key_r.read()

        # decrypt symetric key with private key
        private_key = None
        with open(self.private_key_filename, "rb") as priv_key_file:
            private_key = serialization.load_pem_private_key(priv_key_file.read(), password=self.pem_password, backend=default_backend())
        key_iv = private_key.decrypt(ct_key, padding=padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None,),)
        key = key_iv[0:32]
        iv = key_iv[32:49]
    
        # decrypt file symetric with key and IV
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        ct = None
        with open(filename, "rb") as secret_file:
            ct = secret_file.read()
        data = decryptor.update(ct) + decryptor.finalize()
    
        # remove padding
        data = data[0:length]
        return data


    # sign a file with a private key
    def sign_file(self, filename: str) -> bytes:
        private_key = None
        with open(self.private_key_filename, "rb") as key_file:
            private_key = serialization.load_pem_private_key( key_file.read(),
                    password=self.pem_password, backend=default_backend())

        message = None
        with open(filename, "rb") as file_to_sign:
            message = file_to_sign.read()

        signature = private_key.sign( message, padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return base64.b64encode(signature)
  
  
    # check a signature with a public key
    def check_file_signature(self, filename: str, signature: bytes) -> bool:
        public_key = None
        with open(self.public_key_filename, "rb") as key_file:
            public_key = serialization.load_pem_public_key( key_file.read(), backend=default_backend())

        message = None
        with open(filename, "rb") as file_to_check:
            message = file_to_check.read()

        try:
            public_key.verify(
                base64.b64decode(signature),
                message,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            raise e
