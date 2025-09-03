from Crypto.Cipher import AES
import base64

ZWC_SPACE = '\u200B'
ZWC_JOINER = '\u200C'

def encrypt_message(message, password):
    cipher = AES.new(password.encode('utf-8').ljust(32, b'0'), AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt_message(data, password):
    decoded = base64.b64decode(data)
    nonce, tag, ciphertext = decoded[:16], decoded[16:32], decoded[32:]
    cipher = AES.new(password.encode('utf-8').ljust(32, b'0'), AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

def encode_text_file(input_path, output_path, message, password):
    with open(input_path, 'r', encoding='utf-8') as f:
        original_data = f.read()
    encoded = encrypt_message(message, password)
    hidden_bits = ''.join([bin(ord(ch))[2:].zfill(8) for ch in encoded])
    hidden_data = ''.join([ZWC_SPACE if b == '0' else ZWC_JOINER for b in hidden_bits])
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(original_data + hidden_data)

def decode_text_file(file_path, password):
    with open(file_path, 'r', encoding='utf-8') as f:
        data = f.read()
    hidden_part = ''.join(ch for ch in data if ch in (ZWC_SPACE, ZWC_JOINER))
    hidden_bits = ''.join(['0' if ch == ZWC_SPACE else '1' for ch in hidden_part])
    padding = 8 - (len(hidden_bits) % 8) if len(hidden_bits) % 8 != 0 else 0
    hidden_bits += '0' * padding
    bytes_list = [chr(int(hidden_bits[i:i + 8], 2)) for i in range(0, len(hidden_bits), 8)]
    combined = ''.join(bytes_list)
    return decrypt_message(combined, password)