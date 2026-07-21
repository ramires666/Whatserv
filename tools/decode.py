import base64
import urllib.parse
from google.protobuf.internal import decoder

# Вставь сюда свою ссылку otpauth-migration://offline?data=...
MIGRATION_URL = "otpauth-migration://offline?data=ClgKFJcA5VzpRHxDHwCkMkVK%2FIPkBm6WEh1icml0dGJ5cGFzc2RpYWEyMUBob3RtYWlsLmNvbRoGT3BlbkFJIAEoATACQhM4NmYzZjMxNzgzOTM0Mjc1NDU2EAIYASAA"

def read_varint(data, pos):
    result = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise IndexError("Unexpected EOF while reading varint")
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, pos


def parse_otp_param(data):
    pos = 0
    param = {}
    while pos < len(data):
        key, pos = read_varint(data, pos)
        field_num = key >> 3
        wire_type = key & 0x7

        if wire_type == 2:  # Length-delimited (bytes/string)
            length, pos = read_varint(data, pos)
            val = data[pos : pos + length]
            pos += length

            if field_num == 1:  # secret
                param["secret"] = base64.b32encode(val).decode("utf-8")
            elif field_num == 2:  # name
                param["name"] = val.decode("utf-8", errors="ignore")
            elif field_num == 3:  # issuer
                param["issuer"] = val.decode("utf-8", errors="ignore")
            elif field_num == 6:  # algorithm
                param["algorithm"] = int.from_bytes(val, "big") if val else 0
        elif wire_type == 0:  # Varint
            val, pos = read_varint(data, pos)
            if field_num == 4:  # digits
                param["digits"] = val
            elif field_num == 5:  # type
                param["type"] = val
        else:
            break
    return param


def parse_migration_url(url):
    parsed = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed.query)
    raw_data = query_params.get("data", [""])[0]

    # Добавляем паддинг base64 при необходимости
    missing_padding = len(raw_data) % 4
    if missing_padding:
        raw_data += "=" * (4 - missing_padding)

    decoded_bytes = base64.b64decode(raw_data)

    pos = 0
    accounts = []
    while pos < len(decoded_bytes):
        key, pos = read_varint(decoded_bytes, pos)
        field_num = key >> 3
        wire_type = key & 0x7

        if field_num == 1 and wire_type == 2:  # OtpParameters
            length, pos = read_varint(decoded_bytes, pos)
            param_data = decoded_bytes[pos : pos + length]
            pos += length
            accounts.append(parse_otp_param(param_data))
        elif wire_type == 2:
            length, pos = read_varint(decoded_bytes, pos)
            pos += length
        elif wire_type == 0:
            _, pos = read_varint(decoded_bytes, pos)
        else:
            break

    return accounts


# Выполнение
if __name__ == "__main__":
    try:
        results = parse_migration_url(MIGRATION_URL)

        out_file = "my_keys.txt"
        with open(out_file, "w", encoding="utf-8") as f:
            for item in results:
                issuer = item.get("issuer", "Unknown")
                name = item.get("name", "Unknown")
                secret = item.get("secret", "")
                line = f"Service: {issuer} | Account: {name} | SecretKey: {secret}\n"
                f.write(line)
                print(line.strip())

        print(
            f"\nУспешно распаршено {len(results)} аккаунтов. Все ключи сохранены в '{out_file}'"
        )

    except Exception as e:
        print(f"Ошибка при обработке: {e}")