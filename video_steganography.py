from Crypto.Cipher import AES
import base64

def encrypt_message(message, password):
    cipher = AES.new(password.encode('utf-8').ljust(32, b'0'), AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext)

def decrypt_message(data, password):
    decoded = base64.b64decode(data)
    nonce, tag, ciphertext = decoded[:16], decoded[16:32], decoded[32:]
    cipher = AES.new(password.encode('utf-8').ljust(32, b'0'), AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

def encode_video_file(input_path, output_path, message, password):
    with open(input_path, "rb") as file:
        video_data = file.read()
    encrypted = encrypt_message(message, password)
    with open(output_path, "wb") as file:
        file.write(video_data + b":::" + encrypted)

def decode_video_file(file_path, password):
    with open(file_path, "rb") as file:
        combined_data = file.read()
    if b":::" not in combined_data:
        raise Exception("No hidden data found!")
    _, encrypted_message = combined_data.rsplit(b":::", 1)
    return decrypt_message(encrypted_message, password)