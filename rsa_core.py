"""
RSA Cryptography Core Module
Реализация алгоритма RSA для шифрования и дешифрования сообщений
"""

import random
import base64


def is_prime(n: int, k: int = 10) -> bool:
    """
    Тест Миллера-Рабина на простоту числа
    n - проверяемое число
    k - количество раундов проверки
    """
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # Представляем n-1 как 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Проверка k раз
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)

        if x in (1, n - 1):
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def generate_prime(bits: int) -> int:
    """Генерация случайного простого числа заданной битности"""
    while True:
        # Генерируем случайное нечётное число нужной битности
        p = random.getrandbits(bits)
        p |= (1 << bits - 1) | 1  # Устанавливаем старший бит и младший (нечётное)

        if is_prime(p):
            return p


def gcd(a: int, b: int) -> int:
    """Наибольший общий делитель (алгоритм Евклида)"""
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> tuple:
    """
    Расширенный алгоритм Евклида
    Возвращает (gcd, x, y) где ax + by = gcd
    """
    if a == 0:
        return b, 0, 1

    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1

    return gcd_val, x, y


def mod_inverse(e: int, phi: int) -> int:
    """
    Вычисление модульного обратного элемента
    Находит d такое, что e * d ≡ 1 (mod phi)
    """
    gcd_val, x, _ = extended_gcd(e, phi)

    if gcd_val != 1:
        raise ValueError("Модульное обратное не существует")

    return x % phi


def generate_keypair(bits: int = 1024) -> tuple:
    """
    Генерация пары ключей RSA

    Returns:
        tuple: ((e, n), (d, n)) - публичный и приватный ключи
    """
    # Генерируем два различных простых числа
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)

    while p == q:
        q = generate_prime(bits // 2)

    # Вычисляем n = p * q
    n = p * q

    # Вычисляем функцию Эйлера φ(n) = (p-1)(q-1)
    phi = (p - 1) * (q - 1)

    # Выбираем открытую экспоненту e
    # Обычно используют 65537 (0x10001) - простое число Ферма
    e = 65537

    # Проверяем, что gcd(e, phi) = 1
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)

    # Вычисляем секретную экспоненту d
    d = mod_inverse(e, phi)

    # Публичный ключ (e, n), приватный ключ (d, n)
    return ((e, n), (d, n))


def encrypt_number(m: int, pub_key: tuple) -> int:
    """
    Шифрование числа
    c = m^e mod n
    """
    e, n = pub_key

    if m >= n:
        raise ValueError("Сообщение слишком большое для данного ключа")

    return pow(m, e, n)


def decrypt_number(c: int, priv_key: tuple) -> int:
    """
    Дешифрование числа
    m = c^d mod n
    """
    d, n = priv_key
    return pow(c, d, n)


def text_to_int(text: str) -> int:
    """Преобразование текста в число"""
    return int.from_bytes(text.encode('utf-8'), 'big')


def int_to_text(number: int) -> str:
    """Преобразование числа обратно в текст"""
    if number == 0:
        return ''

    byte_length = (number.bit_length() + 7) // 8
    return number.to_bytes(byte_length, 'big').decode('utf-8')


def encrypt_message(message: str, pub_key: tuple) -> str:
    """
    Шифрование текстового сообщения

    Args:
        message: Исходное сообщение
        pub_key: Публичный ключ (e, n)

    Returns:
        str: Зашифрованное сообщение в Base64 формате
    """
    _, n = pub_key

    # Определяем максимальный размер блока
    # Оставляем небольшой запас для безопасности
    max_bytes = (n.bit_length() - 1) // 8 - 1

    if max_bytes <= 0:
        raise ValueError("Ключ слишком маленький")

    # Размер зашифрованного блока в байтах
    encrypted_block_size = (n.bit_length() + 7) // 8

    # Разбиваем сообщение на блоки
    message_bytes = message.encode('utf-8')
    encrypted_blocks = b''

    for i in range(0, len(message_bytes), max_bytes):
        block = message_bytes[i:i + max_bytes]
        block_int = int.from_bytes(block, 'big')
        encrypted_int = encrypt_number(block_int, pub_key)
        # Каждый блок имеет фиксированный размер для корректного декодирования
        encrypted_blocks += encrypted_int.to_bytes(encrypted_block_size, 'big')

    # Возвращаем в Base64 формате
    return base64.b64encode(encrypted_blocks).decode('ascii')


def decrypt_message(encrypted: str, priv_key: tuple) -> str:
    """
    Дешифрование сообщения

    Args:
        encrypted: Зашифрованное сообщение в Base64 формате
        priv_key: Приватный ключ (d, n)

    Returns:
        str: Расшифрованное сообщение
    """
    _, n = priv_key

    # Декодируем Base64
    encrypted_bytes = base64.b64decode(encrypted)

    # Размер зашифрованного блока
    block_size = (n.bit_length() + 7) // 8

    decrypted_bytes = b''

    # Разбиваем на блоки и дешифруем
    for i in range(0, len(encrypted_bytes), block_size):
        block = encrypted_bytes[i:i + block_size]
        encrypted_int = int.from_bytes(block, 'big')
        decrypted_int = decrypt_number(encrypted_int, priv_key)

        if decrypted_int == 0:
            continue

        byte_length = (decrypted_int.bit_length() + 7) // 8
        decrypted_bytes += decrypted_int.to_bytes(byte_length, 'big')

    return decrypted_bytes.decode('utf-8')


def key_to_string(key: tuple) -> str:
    """Преобразование ключа в строку (простой формат hex)"""
    exp, n = key
    return f"{hex(exp)[2:]}:{hex(n)[2:]}"


def string_to_key(key_str: str) -> tuple:
    """Преобразование строки обратно в ключ (простой формат hex)"""
    parts = key_str.strip().split(':')
    if len(parts) != 2:
        raise ValueError("Неверный формат ключа")

    exp = int(parts[0], 16)
    n = int(parts[1], 16)
    return (exp, n)


# ============== PEM ФОРМАТ (стандартный) ==============

def _ensure_cryptography() -> bool:
    """Проверка наличия библиотеки cryptography"""
    try:
        # pylint: disable=import-outside-toplevel,unused-import
        from cryptography.hazmat.primitives import serialization  # noqa: F401
        return True
    except ImportError:
        return False


def keys_to_pem(pub_key: tuple, priv_key: tuple) -> tuple:
    """
    Преобразование ключей в стандартный PEM формат

    Args:
        pub_key: (e, n) - публичный ключ
        priv_key: (d, n) - приватный ключ

    Returns:
        tuple: (public_pem: str, private_pem: str)
    """
    # pylint: disable=import-outside-toplevel
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        RSAPublicNumbers, RSAPrivateNumbers
    )
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend

    e, n = pub_key
    d, _ = priv_key

    # Для полного приватного ключа нужны p, q и другие параметры
    # Восстанавливаем их из e, d, n
    p, q = _recover_prime_factors(n, e, d)

    # Вычисляем дополнительные параметры CRT
    dp = d % (p - 1)  # d mod (p-1)
    dq = d % (q - 1)  # d mod (q-1)
    qi = mod_inverse(q, p)  # q^(-1) mod p

    # Создаём объекты ключей
    public_numbers = RSAPublicNumbers(e, n)
    private_numbers = RSAPrivateNumbers(p, q, d, dp, dq, qi, public_numbers)

    # Генерируем объекты ключей
    private_key_obj = private_numbers.private_key(default_backend())
    public_key_obj = private_key_obj.public_key()

    # Сериализуем в PEM
    public_pem = public_key_obj.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    private_pem = private_key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    return public_pem, private_pem


def _recover_prime_factors(n: int, e: int, d: int) -> tuple:
    """
    Восстановление простых множителей p и q из n, e, d
    Алгоритм основан на том, что ed - 1 кратно φ(n)
    """
    k = d * e - 1

    while True:
        g = random.randrange(2, n)
        t = k

        while t % 2 == 0:
            t //= 2
            x = pow(g, t, n)

            if x > 1 and gcd(x - 1, n) > 1:
                p = gcd(x - 1, n)
                q = n // p
                if p * q == n:
                    return (min(p, q), max(p, q))


def pem_to_keys(public_pem: str = None, private_pem: str = None) -> tuple:
    """
    Преобразование PEM в ключи (e, n) и (d, n)

    Args:
        public_pem: PEM строка публичного ключа
        private_pem: PEM строка приватного ключа

    Returns:
        tuple: (public_key, private_key) или (public_key, None) или (None, private_key)
    """
    # pylint: disable=import-outside-toplevel
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend

    pub_key = None
    priv_key = None

    if private_pem:
        private_key_obj = serialization.load_pem_private_key(
            private_pem.encode('utf-8'),
            password=None,
            backend=default_backend()
        )
        private_numbers = private_key_obj.private_numbers()
        public_numbers = private_numbers.public_numbers

        pub_key = (public_numbers.e, public_numbers.n)
        priv_key = (private_numbers.d, public_numbers.n)

    elif public_pem:
        public_key_obj = serialization.load_pem_public_key(
            public_pem.encode('utf-8'),
            backend=default_backend()
        )
        public_numbers = public_key_obj.public_numbers()
        pub_key = (public_numbers.e, public_numbers.n)

    return pub_key, priv_key


def is_pem_format(key_str: str) -> bool:
    """Проверяет, является ли строка PEM форматом"""
    return key_str.strip().startswith('-----BEGIN')


# Для тестирования
if __name__ == "__main__":
    print("Генерация ключей RSA (512 бит)...")
    test_public_key, test_private_key = generate_keypair(512)

    print(f"\nПубличный ключ:\n{key_to_string(test_public_key)[:100]}...")
    print(f"\nПриватный ключ:\n{key_to_string(test_private_key)[:100]}...")

    test_message = "Привет, мир! Hello, World!"
    print(f"\nИсходное сообщение: {test_message}")

    test_encrypted = encrypt_message(test_message, test_public_key)
    print(f"\nЗашифровано: {test_encrypted[:100]}...")

    test_decrypted = decrypt_message(test_encrypted, test_private_key)
    print(f"\nРасшифровано: {test_decrypted}")

    print(f"\nСовпадение: {test_message == test_decrypted}")
