from Crypto.Cipher import AES
import base64
import wave
import numpy as np

def encrypt_message(message, password):
    cipher = AES.new(password.encode('utf-8').ljust(32, b'0'), AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt_message(data, password):
    decoded = base64.b64decode(data)
    nonce, tag, ciphertext = decoded[:16], decoded[16:32], decoded[32:]
    cipher = AES.new(password.encode('utf-8').ljust(32, b'0'), AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

def encode_audio_file(input_path, output_path, message, password):
    result = encrypt_message(message, password)
    with wave.open(input_path, 'rb') as wav_file:
        params = wav_file.getparams()
        frames = wav_file.readframes(params.nframes)
    audio_data = np.frombuffer(frames, dtype=np.int16).copy()
    hidden_bits = ''.join(format(byte, '08b') for byte in result.encode())
    if len(hidden_bits) > len(audio_data):
        raise Exception("Audio file too small for this message!")
    for i in range(len(hidden_bits)):
        audio_data[i] = (audio_data[i] & ~1) | int(hidden_bits[i])
    with wave.open(output_path, 'wb') as output_wav:
        output_wav.setparams(params)
        output_wav.writeframes(audio_data.tobytes())

def decode_audio_file(file_path, password):
    with wave.open(file_path, 'rb') as wav_file:
        params = wav_file.getparams()
        frames = wav_file.readframes(params.nframes)
    audio_data = np.frombuffer(frames, dtype=np.int16)
    hidden_bits = ''.join(str(audio_data[i] & 1) for i in range(len(audio_data)))
    hidden_bytes = bytearray()
    for i in range(0, len(hidden_bits), 8):
        byte = hidden_bits[i:i + 8]
        if len(byte) == 8:
            hidden_bytes.append(int(byte, 2))
    return decrypt_message(hidden_bytes, password)