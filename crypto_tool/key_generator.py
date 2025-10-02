import hashlib
import numpy as np
from scipy.stats import chisquare


class KeyGenerator:
    def __init__(self):
        self.key_size = 32  # 256 бит

    def generate_from_passphrase(self, passphrase):
        # Используем PBKDF2 для получения ключа из парольной фразы
        salt = b''  # По требованию, соль не используется
        key = hashlib.pbkdf2_hmac('sha256', passphrase.encode(), salt, 100000, self.key_size)
        return key

    def nist_test(self, data):
        # Преобразуем байты в массив чисел
        data_array = list(data)

        freq = [0] * 256
        for byte in data_array:
            if byte < 256:  # Проверка на случай выхода за границы
                freq[byte] += 1

        # Используем хи-квадрат тест
        expected = [len(data) / 256] * 256
        chi2, p_value = chisquare(freq, f_exp=expected)
        return p_value > 0.01  # Возвращаем True если последовательность случайна