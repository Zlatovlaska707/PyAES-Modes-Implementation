from Crypto.Cipher import AES
from Crypto.Util import Counter
import os


class AESCTR:
    """
    Класс для шифрования/дешифрования данных в режиме AES-CTR.
    Поддерживает ключи длиной 128, 192 и 256 бит.
    """

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("Длина ключа должна составлять 16/24/32 байта (128/192/256 бит).")
        self.key = key

    def encrypt(self, plaintext: bytes, nonce: bytes = None) -> bytes:
        """
        Шифрует данные в режиме CTR.

        -param plaintext: Исходные данные для шифрования
        -param nonce: Опциональный nonce (8 байт). Если не указан - генерируется автоматически.
        -return: Шифротекст в формате nonce + ciphertext
        """
        if nonce is None:
            nonce = os.urandom(8)  # Генерация 8-байтового nonce
        elif len(nonce) != 8:
            raise ValueError("Длина nonce должна составлять 8 байт.")

        # Создание счетчика и шифрование
        counter = Counter.new(64, prefix=nonce, initial_value=0)
        cipher = AES.new(self.key, AES.MODE_CTR, counter=counter)
        return nonce + cipher.encrypt(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        Дешифрует данные в режиме CTR.

        -param ciphertext: Шифротекст в формате nonce + ciphertext
        -return: Расшифрованные данные
        """
        if len(ciphertext) < 8:
            raise ValueError("Invalid ciphertext: missing nonce.")

        # Извлечение nonce и данных
        nonce, data = ciphertext[:8], ciphertext[8:]

        # Восстановление счетчика и дешифрование
        counter = Counter.new(64, prefix=nonce, initial_value=0)
        cipher = AES.new(self.key, AES.MODE_CTR, counter=counter)
        return cipher.decrypt(data)


def main():

    try:
        # Генерация 192-битного ключа (24 байта)
        key = os.urandom(24)

        # Чтение входных данных
        try:
            with open("input.txt", "rb") as f:
                plaintext = f.read()
        except FileNotFoundError:
            print("Файл input.txt не найден. Используется тестовый текст.")
            plaintext = b"Dmitrij, dmitrij@example.com"

        # Шифрование
        ctr = AESCTR(key)
        ciphertext = ctr.encrypt(plaintext)

        # Дешифрование для проверки
        decrypted = ctr.decrypt(ciphertext)

        # Сохранение результатов
        with open("encrypted.txt", "wb") as f:
            f.write(ciphertext)

        with open("decrypted.txt", "wb") as f:
            f.write(decrypted)

        print(f"""
        Успешно!
        Длина исходных данных: {len(plaintext)} байт
        Длина шифротекста: {len(ciphertext)} байт
        Совпадение данных после дешифрования: {plaintext == decrypted}
        Результаты сохранены в encrypted.bin и decrypted.txt
        """)

    except Exception as e:
        print(f"Ошибка: {str(e)}")


if __name__ == "__main__":
    main()