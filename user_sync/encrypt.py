import os
# from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad


class Encryption:
    def __init__(self, pk_file, password, data):
        self.pk_file = pk_file
        self.password = password
        self.data = data.read()

    def create_key(self):
        salt = b'\xe5\x87\x8fa\xed\x0f\x01fl\x91\x05]bd\xd9C\x89\x90N\xbb\xc0\x06\xc3\x03[b8\x0eI\xbc\x12\xdb'
        key = PBKDF2(self.password, salt, dkLen=32)
        return key

    def encrypt_file(self):
        rsa_opening = "-----BEGIN RSA PRIVATE KEY-----".encode()
        if rsa_opening in self.data:
            key = self.create_key()
            cipher = AES.new(key, AES.MODE_CBC)
            ciphered_data = cipher.encrypt(pad(self.data, AES.block_size))
            with open(self.pk_file, "wb") as file_out:
                file_out.write(cipher.iv)
                file_out.write(ciphered_data)
            print("Encryption successful!", os.path.abspath(self.pk_file))
            return ciphered_data
        else:
            print('File has already been encrypted.')

    def decrypt_file(self):
        rsa_opening = "-----BEGIN RSA PRIVATE KEY-----".encode()
        if rsa_opening not in self.data:
            with open(self.pk_file, 'rb') as file_in:
                iv = file_in.read(16)
                ciphered_data = file_in.read()
            key = self.create_key()
            try:
                cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                original_data = unpad(cipher.decrypt(ciphered_data), AES.block_size)
                with open(self.pk_file, 'wb') as file:
                    file.write(original_data)
                print("Decryption successful!", os.path.abspath(self.pk_file))
                return original_data
            except ValueError:
                print('Password was incorrect.')
        else:
            print("File has not been encrypted.")


# if __name__ == '__main__':
#     encrypt = Encryption('../test-config/LDAP/private2.key', 'password')
#     encrypt.encrypt_file()
