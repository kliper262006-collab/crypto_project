import pytest # noqa
import tempfile
import os
from ..cipher import Cipher
from ..key_generator import KeyGenerator


def test_key_generation():
    key_gen = KeyGenerator()
    key = key_gen.generate_from_passphrase("testpass")
    assert len(key) == 32  # 256 бит


def test_encrypt_decrypt():
    key_gen = KeyGenerator()
    key = key_gen.generate_from_passphrase("testpass")
    cipher = Cipher(key)

    # Тестирование шифрования и дешифрования блока
    test_data = b'Hello, World!123'  # 16 байт
    encrypted = cipher.encrypt_block(test_data)
    decrypted = cipher.decrypt_block(encrypted)
    assert decrypted == test_data


def test_file_encryption():
    key_gen = KeyGenerator()
    key = key_gen.generate_from_passphrase("testpass")
    cipher = Cipher(key)

    # Создание временного файла для тестирования
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"Test file content for encryption")
        tmp_name = tmp.name

    try:
        # Шифрование и дешифрование файла
        encrypted_file = tmp_name + '.enc'
        decrypted_file = tmp_name + '.dec'

        cipher.encrypt_file(tmp_name, encrypted_file)
        cipher.decrypt_file(encrypted_file, decrypted_file)

        # Проверка, что исходный и расшифрованный файлы идентичны
        with open(tmp_name, 'rb') as f_orig, open(decrypted_file, 'rb') as f_dec:
            assert f_orig.read() == f_dec.read()

        # Удаление временных файлов
        os.unlink(encrypted_file)
        os.unlink(decrypted_file)
    except Exception as e:
        # Удаление временных файлов в случае ошибки
        if os.path.exists(encrypted_file):
            os.unlink(encrypted_file)
        if os.path.exists(decrypted_file):
            os.unlink(decrypted_file)
        raise e
    finally:
        os.unlink(tmp_name)


def test_nist_randomness():
    key_gen = KeyGenerator()
    key = key_gen.generate_from_passphrase("testpass")

    # Тестирование ключа на случайность
    assert key_gen.nist_test(key) == True