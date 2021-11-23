# генерация ключа симметричного алгоритма шифрования
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

path_encrypt_key = r"D:\\OIB\\symmetric.txt"
path_open_key = r"D:\\OIB\\public.pem"
path_close_key = r"D:\\OIB\\private.pem"
path_text = r"D:\\OIB\\text.txt"
path_text_en = r"D:\\OIB\\en_text.txt"
path_text_ds = r"D:\\OIB\\text_res.txt"


def generation_symmetric_key():
    key = os.urandom(16)
    return key


def generation_asymmetric_keys(type_key):
    keys = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_key = keys
    public_key = keys.public_key()
    if type_key:
        return private_key
    else:
        return public_key


def save_asymmetric_keys_in_the_file(public_key, private_key):
    path_open_key = input("Введите путь для сохранения открытого ключа в файл\n")
    with open(path_open_key, 'wb') as public_out:
        public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo))

    # сериализация закрытого ключа в файл
    path_close_key = input("Введите путь для сохранения закрытого ключа в файл\n")
    with open(path_close_key, 'wb') as private_out:
        private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                    encryption_algorithm=serialization.NoEncryption()))


def symmetric_key_encryption(public_key, key):
    return public_key.encrypt(key,
                              padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                           label=None))


def save_to_file_symmetric_key_encryption(c_text):
    path_encrypt_key = input("Введите путь для сохранения симметричного ключа в файл\n")
    with open(path_encrypt_key, 'wb') as key_file:
        key_file.write(c_text)


def decryption_of_symmetric_key(private_key, c_text):
    return private_key.decrypt(c_text,
                               padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                            label=None))


def text_encryption_and_description(key):
    text_ = ""
    path_text = input("Введите путь к тексту, который нужно зашифровать\n")
    with open(path_text, 'r', encoding='utf-8') as f:
        text_ = f.read()
    from cryptography.hazmat.primitives import padding
    padder = padding.ANSIX923(1024).padder()
    padded_text = padder.update(bytes(text_, 'utf-8')) + padder.finalize()
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    c_text = encryptor.update(padded_text) + encryptor.finalize()
    print("Текст зашифрован!")
    save_to_file_text_encryption(c_text)
    print("Зашифрованный текст записан в файл")
    decryptor = cipher.decryptor()
    dc_text = decryptor.update(c_text) + decryptor.finalize()
    unpadder = padding.ANSIX923(1024).unpadder()
    unpadded_dc_text = unpadder.update(dc_text) + unpadder.finalize()
    print("Текст расшифрован!")
    save_to_file_text_descryption(unpadded_dc_text)


def save_to_file_text_encryption(c_text):
    path_text_en = input("Введите путь для сохранения зашифрованного текста\n")
    with open(path_text_en, 'wb') as f_text:
        f_text.write(c_text)


def save_to_file_text_descryption(ds_text):
    #"D:\\OIB\\des.txt"
    path_text_ds = input("Введите путь для сохранения расшифрованного текста\n")
    with open(path_text_ds, 'w') as f:
        f.write(ds_text.decode("UTF_8"))


sym_key = generation_symmetric_key()
print("Ключ создан!")
close_key = generation_asymmetric_keys(True)
open_key = generation_asymmetric_keys(False)
print("Асимметричные ключи созданы!")
save_asymmetric_keys_in_the_file(open_key, close_key)
print("Асимметричные ключи сохранены в файл!")
c_key = symmetric_key_encryption(open_key, sym_key)
print("Симметричный ключ зашифрован")
text_encryption_and_description(sym_key)

