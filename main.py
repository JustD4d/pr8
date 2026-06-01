import os
import secrets

# Коэффициенты и параметры эллиптической кривой (длина двоичного вектора подписи составляет 512 бит)
P_MOD = 0x4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15DF1D852741AF4704A0458047E80E4546D35B8336FAC224DD81664BBF528BE6373
CURVE_A = 0x7
CURVE_B = 0x1CFF0806A31116DA29D8CFA54E57EB748BC5F377E49400FDD788B649ECA1AC4361834013B2AD7322480A89CA58E0CF74BC9E540C2ADD6897FAD0A3084F302ADC
ORDER_Q = 0x4531ACD1FE0023C7550D267B6B2FEE80922B14B2FFB90F04D4EB7C09B5D2D15DA82F2D7ECB1DBAC719905C5EECC423F1D86E25EDBE23C595D644AAF187E6E6DF
BASE_X = 0x24D19CC64572EE30F396BF6EBBFD7A6C5213B3B3D7057CC825F91093A68CD762FD60611262CD838DC6B60AA7EEE804E28BC849977FAC33B4B530F1B120248A9A
BASE_Y = 0x2BB312A43BD2CE6E0D020613C857ACDDCFBF061E91E5F2C3F32447C259F39B2C83AB156D77F1496BF7EB3351E1EE4E43DC1A18B91B24640B6DBB92CB1ADD371E
BASE_POINT = (BASE_X, BASE_Y)
SIG_LEN_BYTES = 64


class MessageDigestSignature:
    """
    Реализация функции вычисления дайджеста для предварительного сворачивания 
    подписываемого сообщения в строку фиксированной длины (хэш-код).
    """
    def __init__(self, digest_size=512):
        self.digest_size = digest_size // 8
        self.state = b'\x00' * 64
        self.storage = b''
        self.length = 0

    def _compress(self, state: bytes, block: bytes) -> bytes:
        """
        Функция последовательного пошагового сжатия блока сообщения 
        с вектором текущего состояния по модулю два.
        """
        s = list(state)
        b = list(block)
        
        x_stage = [s[i] ^ b[i] for i in range(64)]
        
        for round_idx in range(12):
            for i in range(64):
                x_stage[i] = (x_stage[i] + round_idx + i) % 256
                x_stage[i] ^= x_stage[(i + 1) % 64]
                
        return bytes(x_stage)

    def update(self, data: bytes):
        """Разделение входного сообщения на блоки фиксированной длины."""
        self.storage += data
        self.length += len(data) * 8
        while len(self.storage) >= 64:
            block = self.storage[:64]
            self.storage = self.storage[64:]
            self.state = self._compress(self.state, block)

    def digest(self) -> bytes:
        """Дополнение сообщения до строки фиксированной длины и возврат хэш-кода."""
        padding_len = 64 - len(self.storage)
        padded_block = self.storage + b'\x01' + b'\x00' * (padding_len - 1)
        
        final_state = self._compress(self.state, padded_block)
        
        len_bytes = (self.length % (2**512)).to_bytes(64, byteorder='little')
        final_state = self._compress(final_state, len_bytes)
        
        return final_state[:self.digest_size]


def hash_message(data: bytes) -> bytes:
    """Сворачивание сообщения в строку фиксированной длины."""
    hasher = MessageDigestSignature(digest_size=512)
    hasher.update(data)
    return hasher.digest()


def modinv(a, m):
    """
    Нахождение обратного значения по модулю натурального числа 
    с помощью расширенного алгоритма Евклида.
    """
    return pow(a, -1, m)


def add_points(P, Q):
    """
    Сложение точек эллиптической кривой над конечным полем вычетов 
    по модулю простого числа.
    """
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    
    # Первый случай: складываются две одинаковые точки, используется уравнение касательной
    if x1 == x2 and y1 == y2:
        if y1 == 0:
            return None
        m = (3 * x1 * x1 + CURVE_A) * modinv(2 * y1, P_MOD) % P_MOD
    # Третий случай: складываются две разные точки с равными абсциссами, сумма дает бесконечно удаленную точку
    elif x1 == x2: 
        return None
    # Второй случай: складываются две разные точки, используется уравнение секущей
    else: 
        m = (y2 - y1) * modinv(x2 - x1, P_MOD) % P_MOD
        
    x3 = (m * m - x1 - x2) % P_MOD
    y3 = (m * (x1 - x3) - y1) % P_MOD
    return x3, y3


def multiply_point(k, P):
    """
    Вычисление кратной точки эллиптической кривой с помощью алгоритма 
    удвоения и сложения на основе двоичного представления целого числа.
    """
    res = None
    addend = P
    while k:
        if k & 1: 
            res = add_points(res, addend)
        addend = add_points(addend, addend)
        k >>= 1
    return res


def generate_keys():
    """Генерация ключевой пары: ключа подписи d и ключа проверки Q."""
    d = secrets.randbelow(ORDER_Q - 1) + 1
    Q = multiply_point(d, BASE_POINT)
    return d, Q


def sign(private_key, data_bytes):
    """Процедура формирования электронной цифровой подписи."""
    # Шаг 1: Вычислить хэш-код сообщения
    h = hash_message(data_bytes)
    # Шаг 2: Вычислить целое число а и определить е
    e = int.from_bytes(h, byteorder='big') % ORDER_Q
    if e == 0:
        e = 1
    
    while True:
        # Шаг 3: Сгенерировать случайное целое число k
        k = secrets.randbelow(ORDER_Q - 1) + 1
        # Шаг 4: Вычислить точку эллиптической кривой С и определить r
        C = multiply_point(k, BASE_POINT)
        r = C[0] % ORDER_Q
        if r == 0:
            continue
        # Шаг 5: Вычислить значение s
        s = (r * private_key + k * e) % ORDER_Q
        if s == 0:
            continue
        # Шаг 6: Вычислить двоичные векторы и определить цифровую подпись как конкатенацию r и s
        return (r.to_bytes(SIG_LEN_BYTES, 'big') + 
                s.to_bytes(SIG_LEN_BYTES, 'big'))


def verify(public_key, data_bytes, signature):
    """Процедура проверки электронной цифровой подписи."""
    if len(signature) != SIG_LEN_BYTES * 2:
        return False
    
    # Шаг 1: По полученной подписи вычислить целые числа r и s
    r = int.from_bytes(signature[:SIG_LEN_BYTES], 'big')
    s = int.from_bytes(signature[SIG_LEN_BYTES:], 'big')
    
    # Шаг 2: Проверка неравенств для r и s
    if not (0 < r < ORDER_Q) or not (0 < s < ORDER_Q):
        return False
    
    # Шаг 3: Вычислить хэш-код сообщения
    h = hash_message(data_bytes)
    # Шаг 4: Вычислить целое число а и определить е
    e = int.from_bytes(h, byteorder='big') % ORDER_Q
    if e == 0:
        e = 1
    
    # Шаг 5: Вычислить значение v
    v = modinv(e, ORDER_Q)
    # Шаг 6: Вычислить значения z1 и z2
    z1 = (s * v) % ORDER_Q
    z2 = (-r * v) % ORDER_Q
    
    # Шаг 7: Вычислить точку эллиптической кривой С и определить значение R
    C = add_points(multiply_point(z1, BASE_POINT), 
                   multiply_point(z2, public_key))
    if C is None:
        return False
    
    # Шаг 8: Проверить равенство R и r
    return (C[0] % ORDER_Q) == r


def read_file_bytes(prompt):
    """Принимать на вход файл с запоминающего устройства для чтения содержимого."""
    while True:
        fname = input(prompt).strip()
        fname = fname.strip('"').strip("'")
        if os.path.exists(fname):
            with open(fname, "rb") as f:
                data = f.read()
            print(f"Файл '{fname}' прочитан. Количество последовательных строк бит: {len(data)}.")
            return data, fname
        else:
            print(f"Ошибка: файл '{fname}' не найден.")


def main():
    while True:
        print("\n" + "="*60)
        print("ПРОГРАММА ЭЛЕКТРОННОЙ ЦИФРОВОЙ ПОДПИСИ")
        print("Процессы формирования и проверки электронной цифровой подписи")
        print("="*60)
        print("1. Сгенерировать ключевую пару")
        print("2. Сформировать электронную цифровую подпись")
        print("3. Проверить электронную цифровую подпись")
        print("0. Выход")
        print("-" * 60)

        choice = input("Выберите действие (введите цифру): ").strip()

        if choice == '1':
            print("\n[Генерация ключевой пары]")
            d, Q = generate_keys()

            priv_name = "secret.key"
            pub_name = "shared.key"

            with open(priv_name, "wb") as f:
                f.write(d.to_bytes(SIG_LEN_BYTES, 'big'))
            with open(pub_name, "wb") as f:
                f.write(Q[0].to_bytes(SIG_LEN_BYTES, 'big') + 
                        Q[1].to_bytes(SIG_LEN_BYTES, 'big'))

            print("Ключ подписи и ключ проверки успешно сформированы.")
            print(f"Ключ подписи (закрытый ключ): {priv_name}")
            print(f"Ключ проверки (открытый ключ): {pub_name}")

        elif choice == '2':
            print("\n[Формирование электронной цифровой подписи]")
            doc_data, doc_name = read_file_bytes("Введите имя файла для формирования подписи: ")

            print("\nВведите имя файла, содержащего ключ подписи (secret.key):")
            key_data, _ = read_file_bytes("-> ")
            d = int.from_bytes(key_data, 'big')

            print("\nВыработка электронной цифровой подписи...")
            sig = sign(d, doc_data)

            sig_name = doc_name + ".sig"
            with open(sig_name, "wb") as f:
                f.write(sig)

            print("Электронная цифровая подпись успешно выработана.")
            print(f"Длина строки подписи: {len(sig)*8} бит")
            print(f"Строка бит присоединена и сохранена в файл: {sig_name}")

        elif choice == '3':
            print("\n[Проверка электронной цифровой подписи]")
            print("Введите имя файла для проверки подписи:")
            doc_data, _ = read_file_bytes("-> ")

            print("\nВведите имя файла, содержащего электронную цифровую подпись:")
            sig_data, _ = read_file_bytes("-> ")

            print("\nВведите имя файла, содержащего ключ проверки подписи (shared.key):")
            key_data, _ = read_file_bytes("-> ")

            Qx = int.from_bytes(key_data[:SIG_LEN_BYTES], 'big')
            Qy = int.from_bytes(key_data[SIG_LEN_BYTES:], 'big')
            Q = (Qx, Qy)

            print("\nВыполняется процедура проверки электронной цифровой подписи...")
            if verify(Q, doc_data, sig_data):
                print("РЕЗУЛЬТАТ: Электронная цифровая подпись верна.")
                print("Контроль целостности и авторство лица успешно подтверждены.")
            else:
                print("ОШИБКА: Электронная цифровая подпись неверна.")
                print("Сообщение содержит искажения или применен неверный ключ проверки.")

        elif choice == '0':
            print("\nЗавершение работы программы.")
            break
        else:
            print("Ошибка ввода. Введите цифру из предложенного перечня.")


if __name__ == '__main__':
    main()
