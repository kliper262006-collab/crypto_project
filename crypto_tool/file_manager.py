import os
import logging
from cipher import Cipher
from key_generator import KeyGenerator

logger = logging.getLogger(__name__)

def encrypt_directory(cipher, input_dir, output_dir, base64=False):
    for root, dirs, files in os.walk(input_dir):
        for file in files:
            input_path = os.path.join(root, file)
            rel_path = os.path.relpath(input_path, input_dir)
            output_path = os.path.join(output_dir, rel_path + '.enc')
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            cipher.encrypt_file(input_path, output_path, base64)

def decrypt_directory(cipher, input_dir, output_dir, base64=False):
    for root, dirs, files in os.walk(input_dir):
        for file in files:
            if file.endswith('.enc'):
                input_path = os.path.join(root, file)
                rel_path = os.path.relpath(input_path, input_dir)
                output_path = os.path.join(output_dir, rel_path[:-4])  # Убираем .enc
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                cipher.decrypt_file(input_path, output_path, base64)