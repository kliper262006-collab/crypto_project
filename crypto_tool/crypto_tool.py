import argparse
import logging
import os
from cipher import Cipher
from key_generator import KeyGenerator
from file_manager import encrypt_directory, decrypt_directory


def setup_logging(verbose):
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


def main():
    parser = argparse.ArgumentParser(description='Утилита для шифрования и дешифрования файлов')
    parser.add_argument('-e', '--encrypt', action='store_true', help='Режим шифрования')
    parser.add_argument('-d', '--decrypt', action='store_true', help='Режим дешифрования')
    parser.add_argument('-i', '--input', required=True, help='Входной файл или директория')
    parser.add_argument('-o', '--output', required=True, help='Выходной файл или директория')
    parser.add_argument('-p', '--passphrase', required=True, help='Парольная фраза')
    parser.add_argument('-b', '--base64', action='store_true', help='Кодировать вывод в base64')
    parser.add_argument('-v', '--verbose', action='store_true', help='Подробное логирование')

    args = parser.parse_args()
    setup_logging(args.verbose)

    # Генерация ключа из парольной фразы
    key_gen = KeyGenerator()
    key = key_gen.generate_from_passphrase(args.passphrase)

    # Проверка ключа на случайность
    if not key_gen.nist_test(key):
        logging.warning("Ключ не прошел тест на случайность")

    cipher = Cipher(key)

    if args.encrypt:
        if os.path.isdir(args.input):
            encrypt_directory(cipher, args.input, args.output, args.base64)
        else:
            cipher.encrypt_file(args.input, args.output, args.base64)
    elif args.decrypt:
        if os.path.isdir(args.input):
            decrypt_directory(cipher, args.input, args.output, args.base64)
        else:
            cipher.decrypt_file(args.input, args.output, args.base64)


if __name__ == '__main__':
    main()