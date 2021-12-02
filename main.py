import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding


def generation_symmetric_key() -> None:
    """
    Записывает по указанному пути в файл сгенерированный случайный ключ.
    """
    key = os.urandom(16)
    key_path = input("Ключ создан.\nВведите путь для файла, в который его нужно сохранить: ")
    with open(key_path, "wb") as f:
        f.write(key)
    print("Ключ записан в файл!\n")


def generation_asymmetric_keys() -> None :
    """
    Записывает по указанным путям в файл сгенерированные асимметричные открытый и закрытый ключи.
    Parameters
    ----------
    """
    keys = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_key = keys
    print(type(private_key))
    public_key = keys.public_key()
    print("Асимметричные ключи созданы!\n")
    path_open_key = input("Введите путь для сохранения открытого ключа в файл: \n")
    with open(path_open_key, 'wb') as public_out:
        public_out.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo))
    path_close_key = input("Введите путь для сохранения закрытого ключа в файл: \n")
    with open(path_close_key, 'wb') as private_out:
        private_out.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                    encryption_algorithm=serialization.NoEncryption()))
    print("Асимметричные ключи записаны в файл!\n")


def symmetric_key_encryption() -> None:
    """
     Считывает из файла сгенерированный симметричный ключ, шифрует его и
     записывает по указанному пути в файл зашифрованный симметричный ключ.
    """
    path_open_key = input("Введите путь, где хранится открытый ключ: ")
    with open(path_open_key, "rb") as pem_in:
        public_bytes = pem_in.read()
    d_public_key = load_pem_public_key(public_bytes)
    print(d_public_key)
    key_path = input("Введите путь, где лежит файл с ключом: ")
    with open(key_path, "rb") as f:
        key = f.read()
    c_key = d_public_key.encrypt(key,
                                 padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                              label=None))
    en_key_path = input("Введите путь для сохранения зашифрованного симметричного ключа в файл: ")
    with open(en_key_path, "wb") as f:
        f.write(c_key)


def decryption_of_symmetric_key() -> None:
    """
     Считывает из файла зашифрованный симметричный ключ, дешифрует его и
     записывает по указанному пути в файл.
    """
    en_key_path = input("Введите путь зашифрованного ключа: ")
    with open(en_key_path, mode="rb") as f:
        en_text = f.read()
    private_pem = input("Введите путь, по которому лежит файл с закрытым ключом: ")
    with open(private_pem, 'rb') as pem_in:
        private_bytes = pem_in.read()
    d_private_key = load_pem_private_key(private_bytes, password=None,)
    dc_key = d_private_key.decrypt(en_text,
                                   padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                                label=None))
    ds_key_path = input("Текст расшифрован!\nВведите путь для сохранения расшифрованного ключа: ")
    with open(ds_key_path, "wb") as f:
        f.write(dc_key)
    print("Дешифрованный ключ сохранен в файл!\n")


def set_iv_to_file() -> None:
    """
    Генерирует ключ для щифрации и дещифрации текста и сохраняет его в бинарный файл.
    """
    iv = os.urandom(8)
    print(type(iv))
    tmp = {bytes(0): iv}
    with open("iv.bin", 'wb') as key_file:
        key_file.write(iv)


def get_iv() -> bytes:
    """
    Считывает из файла ключ для щифрации и дешифрации текста.
    Returns
    --------
        bytes: сгенерированный ключ
    """
    result = 0
    with open("iv.bin", "rb") as f:
        result = f.read()
    return result


def text_encryption() -> None:
    """
    Считывает текст из файла, шифрует его и сохраняет результат в файл по указанному пути
    """
    text_ = ""
    path_text = input("Введите путь к тексту, который нужно зашифровать\n")
    with open(path_text, 'r', encoding='utf-8') as f:
        text_ = f.read()
    key_path = input("Введите путь, где лежит файл с ключом: ")
    with open(key_path, "rb") as f:
        key = f.read()
    set_iv_to_file()
    iv = get_iv()
    padder = padding.ANSIX923(1024).padder()
    padded_text = padder.update(bytes(text_, 'utf-8')) + padder.finalize()
    cipher = Cipher(algorithms.CAST5(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    c_text = encryptor.update(padded_text) + encryptor.finalize()
    print("Текст зашифрован!")
    save_to_file_text_encryption(c_text)


def text_decryption() -> None:
    """
    Считывает из файла зашифрованный текст, дешифрует его и сохраняет результат в файл по указанному пути.
    """
    path_en_text = input("Введите путь к зашифрованному тексту: ")
    with open(path_en_text, 'rb') as f:
        en_text = f.read()
    path_key = input("Введите путь, где хранится файл с ключом: ")
    with open(path_key, "rb") as f:
        key = f.read()
    cipher = Cipher(algorithms.CAST5(key), modes.CBC(get_iv()))
    decryptor = cipher.decryptor()
    dc_text = decryptor.update(en_text) + decryptor.finalize()
    unpadder = padding.ANSIX923(1024).unpadder()
    unpadded_dc_text = unpadder.update(dc_text) + unpadder.finalize()
    print("Текст расшифрован!")
    save_to_file_text_descryption(unpadded_dc_text)


def save_to_file_text_encryption(c_text):
    """
    Сохраняет зашифрованный текст в файл.
    Parameters
    ----------
        c_text: bytes
            зашифрованный текст
    """
    path_text_en = input("Введите путь для сохранения зашифрованного текста\n")
    with open(path_text_en, 'wb') as f_text:
        f_text.write(c_text)


def save_to_file_text_descryption(ds_text):
    """
       Сохраняет дешифрованный текст в файл.
       Parameters
       ----------
           ds_text: str
               дешифрованный текст
       """
    path_text_ds = input("Введите путь для сохранения расшифрованного текста\n")
    with open(path_text_ds, 'w') as f:
        f.write(ds_text.decode("UTF_8"))


print("Вас приветствует программа гибридной криптосистемы.")
end_of_the_work = False
while not end_of_the_work:
    choice = int(input('Выберите номер опции,которую хоите применить:\n1. Сгенерировать ключи\n2. Зашифровать '
                       'текст/ключ\n3.Дешифровать текст/ключ\n4.Выход\n'))
    if choice == 1:
        generation_symmetric_key()
        generation_asymmetric_keys()
    if choice == 2:
        en_choice = int(input("Зашифровать:\n1. Симметричный ключ\n2. Текст\n"))
        if en_choice == 1:
            symmetric_key_encryption()
        if en_choice == 2:
            text_encryption()
        # сохранить его в файл
    if choice == 3:
        dc_choice = int(input("Дешифровать:\n1. Симметричный ключ\n2. Текст\n"))
        if dc_choice == 1:
            decryption_of_symmetric_key()
        if dc_choice == 2:
            text_decryption()
    if choice == 4:
        break
    cont = input("Продолжить работу программы? ")
    if cont == "да":
        continue
    if cont == "нет":
        end_of_the_work = True
