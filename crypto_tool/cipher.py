import os
import json
import logging
import time
import random
import struct
from base64 import b64encode, b64decode

logger = logging.getLogger(__name__)


class Cipher:
    def __init__(self, key):
        self.key = key
        self.block_size = 16  # 128 бит
        self.max_speed = 2 * 1024 * 1024  # 2 МБ/с

        # Генерация S-блоков и таблиц перестановок на основе ключа
        self.sbox1 = self.generate_sbox(self.key[:8])
        self.sbox2 = self.generate_sbox(self.key[16:24])
        self.perm1 = self.generate_permutation(self.key[8:16], self.block_size)
        self.perm2 = self.generate_permutation(self.key[24:32], self.block_size)

        # Генерация обратных преобразований для дешифрования
        self.inv_sbox1 = self.generate_inverse_sbox(self.sbox1)
        self.inv_sbox2 = self.generate_inverse_sbox(self.sbox2)
        self.inv_perm1 = self.generate_inverse_permutation(self.perm1)
        self.inv_perm2 = self.generate_inverse_permutation(self.perm2)

    def generate_sbox(self, seed):
        random.seed(int.from_bytes(seed, byteorder='big'))
        sbox = list(range(256))
        random.shuffle(sbox)
        return sbox

    def generate_permutation(self, seed, size):
        random.seed(int.from_bytes(seed, byteorder='big'))
        perm = list(range(size))
        random.shuffle(perm)
        return perm

    def generate_inverse_sbox(self, sbox):
        inv_sbox = [0] * 256
        for i, val in enumerate(sbox):
            inv_sbox[val] = i
        return inv_sbox

    def generate_inverse_permutation(self, perm):
        inv_perm = [0] * len(perm)
        for i, val in enumerate(perm):
            inv_perm[val] = i
        return inv_perm

    def substitute(self, data, sbox):
        return bytes([sbox[b] for b in data])

    def permute(self, data, perm):
        return bytes([data[i] for i in perm])

    def encrypt_block(self, block):
        # Два шага подстановки и два шага перестановки
        block = self.substitute(block, self.sbox1)
        block = self.permute(block, self.perm1)
        block = self.substitute(block, self.sbox2)
        block = self.permute(block, self.perm2)
        return block

    def decrypt_block(self, block):
        # Обратные преобразования в обратном порядке
        block = self.permute(block, self.inv_perm2)
        block = self.substitute(block, self.inv_sbox2)
        block = self.permute(block, self.inv_perm1)
        block = self.substitute(block, self.inv_sbox1)
        return block

    def pad(self, data):
        pad_len = self.block_size - (len(data) % self.block_size)
        return data + bytes([pad_len] * pad_len)

    def unpad(self, data):
        pad_len = data[-1]
        return data[:-pad_len]

    def encrypt_file(self, input_path, output_path, base64=False):
        start_time = time.time()
        processed_bytes = 0

        # Чтение и шифрование метаданных
        file_name = os.path.basename(input_path)
        file_size = os.path.getsize(input_path)
        metadata = json.dumps({'name': file_name, 'size': file_size}).encode()
        padded_metadata = self.pad(metadata)

        # Шифруем метаданные поблочно
        encrypted_metadata = b''
        for i in range(0, len(padded_metadata), self.block_size):
            block = padded_metadata[i:i + self.block_size]
            encrypted_metadata += self.encrypt_block(block)

        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            # Записываем размер и зашифрованные метаданные
            f_out.write(struct.pack('I', len(encrypted_metadata)))
            f_out.write(encrypted_metadata)

            # Читаем и шифруем данные файла
            data = f_in.read()
            padded_data = self.pad(data)
            for i in range(0, len(padded_data), self.block_size):
                block = padded_data[i:i + self.block_size]
                encrypted_block = self.encrypt_block(block)
                f_out.write(encrypted_block)

                # Контроль скорости
                processed_bytes += len(block)
                elapsed = time.time() - start_time
                expected_time = processed_bytes / self.max_speed
                if elapsed < expected_time:
                    time.sleep(expected_time - elapsed)

        logger.info(f"Зашифрован файл: {input_path} -> {output_path}")

        if base64:
            with open(output_path, 'rb') as f:
                data = f.read()
            with open(output_path, 'wb') as f:
                f.write(b64encode(data))

    def decrypt_file(self, input_path, output_path, base64=False):
        start_time = time.time()
        processed_bytes = 0

        if base64:
            with open(input_path, 'rb') as f:
                data = b64decode(f.read())
            with open(input_path, 'wb') as f:
                f.write(data)

        with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            # Чтение и расшифровка метаданных
            metadata_size = struct.unpack('I', f_in.read(4))[0]
            encrypted_metadata = f_in.read(metadata_size)

            # Дешифруем метаданные поблочно
            decrypted_metadata = b''
            for i in range(0, len(encrypted_metadata), self.block_size):
                block = encrypted_metadata[i:i + self.block_size]
                decrypted_metadata += self.decrypt_block(block)

            decrypted_metadata = self.unpad(decrypted_metadata)
            metadata = json.loads(decrypted_metadata.decode())
            original_size = metadata['size']

            # Читаем и дешифруем данные файла
            encrypted_data = f_in.read()
            decrypted_data = b''
            for i in range(0, len(encrypted_data), self.block_size):
                block = encrypted_data[i:i + self.block_size]
                decrypted_block = self.decrypt_block(block)
                decrypted_data += decrypted_block

                # Контроль скорости
                processed_bytes += len(block)
                elapsed = time.time() - start_time
                expected_time = processed_bytes / self.max_speed
                if elapsed < expected_time:
                    time.sleep(expected_time - elapsed)

            # Обрезаем данные до оригинального размера
            decrypted_data = decrypted_data[:original_size]
            f_out.write(decrypted_data)

        logger.info(f"Расшифрован файл: {input_path} -> {output_path}")