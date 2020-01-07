import os
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


def test_create_key(private_key):
    with open(private_key, "rb") as data:
        password = 'password'
        encryption = user_sync.encrypt.Encryption(private_key, password, data)
        encryption.create_key()
        key = b'\xdf\xbc6\x95\x96\xe0N\xdd\x84\x82\x8eP\xef#GE\x82r\x98\xe8I\x1a\x13D\x16/U\x85\xd7\xc5Ho'
        assert encryption.create_key() == key


def test_encrypt_file(private_key):
    with open(private_key, "rb") as data:
        password = 'password'
        encryption = user_sync.encrypt.Encryption(private_key, password, data)
        result = encryption.encrypt_file()
        rsa_opening = "-----BEGIN RSA PRIVATE KEY-----".encode()
        assert result
        assert rsa_opening not in result


def test_decrypt_file(encrypted_key):
    with open(encrypted_key, 'rb') as data:
        password = 'password'
        decryption = user_sync.encrypt.Encryption(encrypted_key, password, data)
        result = decryption.decrypt_file()
        rsa_opening = "-----BEGIN RSA PRIVATE KEY-----".encode()
        assert rsa_opening in result
    with open(encrypted_key, 'rb') as file:
        data = file.read()
        assert rsa_opening in data

