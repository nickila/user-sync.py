import os
# from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import re
# from Crypto.Hash import SHA256


class Encryption:
    def __init__(self, pk_file, password):
        self.pk_file = pk_file
        self.key = self.create_key(password)
        with open(pk_file, 'rb') as data:
            self.data = data.read()

    def create_key(self, password):
        salt = b'\xe5\x87\x8fa\xed\x0f\x01fl\x91\x05]bd\xd9C\x89\x90N\xbb\xc0\x06\xc3\x03[b8\x0eI\xbc\x12\xdb'
        return PBKDF2(password, salt, dkLen=32)

    def encrypt_file(self):
        pattern = re.compile('\\\\x[A-aZ-z0-9]{0,3}\\\\')
        pattern_occurs = len(pattern.findall(str(self.data)))
        if pattern_occurs < 100:
            cipher = AES.new(self.key, AES.MODE_CBC)
            ciphered_data = cipher.encrypt(pad(self.data, AES.block_size))
            with open(self.pk_file, "wb") as file_out:
                file_out.write(cipher.iv)
                file_out.write(ciphered_data)
            print("Encryption successful!", os.path.abspath(self.pk_file))
            return ciphered_data
        else:
            print('File has already been encrypted.')
            return

    def decrypt_file(self):
        with open(self.pk_file, 'rb') as file_in:
            iv = file_in.read(16)
            ciphered_data = file_in.read()
        try:
            cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
            original_data = unpad(cipher.decrypt(ciphered_data), AES.block_size)
            with open(self.pk_file, 'wb') as file:
                file.write(original_data)
            print("Decryption successful!", os.path.abspath(self.pk_file))
            return original_data
        except ValueError:
            print('Password was incorrect or file is not encrypted.')
            return


# if __name__ == '__main__':
#     encrypt = Encryption('../test-config/LDAP/private2.key', 'password')
#     encrypt.encrypt_file()
