import os
import re
import pytest
import shutil
import user_sync.encrypt


@pytest.fixture
def private_key(fixture_dir, tmpdir):
    shutil.copy(os.path.join(fixture_dir, 'test_private.key'), tmpdir.dirname)
    return os.path.join(tmpdir.dirname, 'test_private.key')


@pytest.fixture
def encrypted_key(fixture_dir, tmpdir):
    shutil.copy(os.path.join(fixture_dir, 'encrypted.key'), tmpdir.dirname)
    return os.path.join(tmpdir.dirname, 'encrypted.key')


def check_pattern(key_file):
    pattern = re.compile('\\\\x[A-aZ-z0-9]{0,3}\\\\')
    with open(key_file, "rb") as file:
        data = file.read()
    return len(pattern.findall(str(data)))


def test_create_key(private_key):
    password = 'password'
    invalid_password = 'wrong_password'
    encryption = user_sync.encrypt.Encryption(private_key, password)
    key = b'\xdf\xbc6\x95\x96\xe0N\xdd\x84\x82\x8eP\xef#GE\x82r\x98\xe8I\x1a\x13D\x16/U\x85\xd7\xc5Ho'
    assert encryption.create_key(password) == key
    assert encryption.create_key(invalid_password) != key


def test_encrypt_file(private_key, encrypted_key):
    password = 'password'
    encryption = user_sync.encrypt.Encryption(private_key, password)
    encryption.encrypt_file()
    assert check_pattern(private_key) > 100
    # Try using the wrong password
    invalid_password = 'wrong_password'
    encryption = user_sync.encrypt.Encryption(private_key, invalid_password)
    assert not encryption.encrypt_file()
    # Try encrypting an already encrypted file
    encryption = user_sync.encrypt.Encryption(encrypted_key, password)
    assert not encryption.encrypt_file()


def test_decrypt_file(encrypted_key, private_key):
    password = 'password'
    decryption = user_sync.encrypt.Encryption(encrypted_key, password)
    decryption.decrypt_file()
    assert check_pattern(encrypted_key) < 100
    # Try using the wrong password
    invalid_password = 'wrong_password'
    decryption = user_sync.encrypt.Encryption(encrypted_key, invalid_password)
    assert not decryption.decrypt_file()
    # Try using an already decrypted file
    decryption = user_sync.encrypt.Encryption(private_key, password)
    assert not decryption.decrypt_file()


def test_encrypt_and_decrypt(private_key):
    password = 'password'
    assert check_pattern(private_key) < 100
    encryption = user_sync.encrypt.Encryption(private_key, password)
    encryption.encrypt_file()
    assert check_pattern(private_key) > 100
    decryption = user_sync.encrypt.Encryption(private_key, password)
    decryption.decrypt_file()
    assert check_pattern(private_key) < 100






