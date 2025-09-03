import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
import wave
import numpy as np
import os
import base64
import cv2
import struct

class HideStreamApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("HIDE STREAM - Where Data Meets Security!")
        self.geometry("700x540")
        self.configure(bg='#e9ecef')
        self.file_path = None
        self.selected_action = None
        self.create_home_page()

    def clear_window(self):
        for widget in self.winfo_children():
            widget.destroy()

    def create_home_page(self):
        self.clear_window()
        tk.Label(self, text="HIDESTREAM", font=("Segoe UI", 28, 'bold'), bg='#e9ecef', fg='#343a40').pack(pady=20)
        tk.Label(self, text="Where Data Meets Security!", font=("Segoe UI", 16), bg='#e9ecef', fg='#495057').pack(pady=10)

        tk.Button(self, text="Text Steganography", width=30, height=2, font=("Segoe UI", 14), 
                  command=lambda: self.select_steganography_type("text")).pack(pady=10)
        tk.Button(self, text="Image Steganography", width=30, height=2, font=("Segoe UI", 14), 
                  command=lambda: self.select_steganography_type("image")).pack(pady=10)
        tk.Button(self, text="Audio Steganography", width=30, height=2, font=("Segoe UI", 14), 
                  command=lambda: self.select_steganography_type("audio")).pack(pady=10)
        tk.Button(self, text="Video Steganography", width=30, height=2, font=("Segoe UI", 14), 
                  command=lambda: self.select_steganography_type("video")).pack(pady=10)

    def select_steganography_type(self, steg_type):
        self.steg_type = steg_type
        self.page2()

    def page2(self):
        self.clear_window()
        type_text = self.steg_type.capitalize()
        tk.Label(self, text=f"Choose Action for {type_text} Steganography", font=("Segoe UI", 20, 'bold'), bg='#e9ecef', fg='#343a40').pack(pady=30)

        tk.Button(self, text="Encode", width=20, height=2, font=("Segoe UI", 14), command=self.encode_page).pack(pady=10)
        tk.Button(self, text="Decode", width=20, height=2, font=("Segoe UI", 14), command=self.decode_page).pack(pady=10)
        tk.Button(self, text="Back", width=20, height=2, font=("Segoe UI", 14), command=self.create_home_page).pack(pady=30)

    def encode_page(self):
        self.clear_window()
        type_text = self.steg_type.capitalize()
        tk.Label(self, text=f"{type_text} Steganography - Encode", font=("Segoe UI", 20, 'bold'), bg='#e9ecef', fg='#343a40').pack(pady=20)

        file_button = tk.Button(self, text="Select File", width=20, font=("Segoe UI", 14), command=self.select_file)
        file_button.pack(pady=10)

        self.file_label = tk.Label(self, text="No file selected", bg='#e9ecef', fg='#6c757d', font=("Segoe UI", 12))
        self.file_label.pack(pady=5)

        tk.Label(self, text="Secret Message:", bg='#e9ecef', fg='#343a40', font=("Segoe UI", 14)).pack(pady=5)
        self.msg_entry = tk.Entry(self, width=50, font=("Segoe UI", 14))
        self.msg_entry.pack(pady=5)

        tk.Label(self, text="Password:", bg='#e9ecef', fg='#343a40', font=("Segoe UI", 14)).pack(pady=5)
        self.pass_entry = tk.Entry(self, width=50, font=("Segoe UI", 14), show='*')
        self.pass_entry.pack(pady=5)

        tk.Button(self, text="Encode & Save", width=20, font=("Segoe UI", 14), command=self.encode_file).pack(pady=20)
        tk.Button(self, text="Back", width=20, font=("Segoe UI", 14), command=self.page2).pack()

    def decode_page(self):
        self.clear_window()
        type_text = self.steg_type.capitalize()
        tk.Label(self, text=f"{type_text} Steganography - Decode", font=("Segoe UI", 20, 'bold'), bg='#e9ecef', fg='#343a40').pack(pady=20)

        file_button = tk.Button(self, text="Select File", width=20, font=("Segoe UI", 14), command=self.select_file)
        file_button.pack(pady=10)

        self.file_label = tk.Label(self, text="No file selected", bg='#e9ecef', fg='#6c757d', font=("Segoe UI", 12))
        self.file_label.pack(pady=5)

        tk.Label(self, text="Password:", bg='#e9ecef', fg='#343a40', font=("Segoe UI", 14)).pack(pady=5)
        self.pass_entry = tk.Entry(self, width=50, font=("Segoe UI", 14), show='*')
        self.pass_entry.pack(pady=5)

        tk.Button(self, text="Decode Message", width=20, font=("Segoe UI", 14), command=self.decode_file).pack(pady=20)
        tk.Button(self, text="Back", width=20, font=("Segoe UI", 14), command=self.page2).pack()

    def select_file(self):
        if self.steg_type == "text":
            self.file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        elif self.steg_type == "image":
            self.file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png *.jpg *.jpeg")])
        elif self.steg_type == "audio":
            self.file_path = filedialog.askopenfilename(filetypes=[("Audio Files", "*.wav")])
        else:  # video
            self.file_path = filedialog.askopenfilename(filetypes=[("Video Files", "*.mp4 *.avi")])

        if self.file_path:
            filename = os.path.basename(self.file_path)
            self.file_label.config(text=f"Selected: {filename}")

    def encode_file(self):
        if not self.file_path or not self.msg_entry.get() or not self.pass_entry.get():
            messagebox.showerror("Error", "All fields are required!")
            return

        if self.steg_type == "text":
            self.encode_text_file()
        elif self.steg_type == "image":
            self.encode_image_file()
        elif self.steg_type == "audio":
            self.encode_audio_file()
        else:
            self.encode_video_file()

    def decode_file(self):
        if not self.file_path or not self.pass_entry.get():
            messagebox.showerror("Error", "All fields are required!")
            return

        if self.steg_type == "text":
            self.decode_text_file()
        elif self.steg_type == "image":
            self.decode_image_file()
        elif self.steg_type == "audio":
            self.decode_audio_file()
        else:
            self.decode_video_file()

    # ===============================
    # TEXT STEGANOGRAPHY
    # ===============================
    def encode_text_file(self):
        ZWC_SPACE = '\u200B'
        ZWC_JOINER = '\u200C'

        with open(self.file_path, 'r', encoding='utf-8') as f:
            original_data = f.read()

        secret_msg = self.msg_entry.get()
        password = self.pass_entry.get()
        cipher = AES.new(password.encode('utf-8').ljust(32, b'0'), AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(secret_msg.encode())
        result = base64.b64encode(cipher.nonce + tag + ciphertext).decode()

        hidden_bits = ''.join([bin(ord(ch))[2:].zfill(8) for ch in result])
        hidden_data = ''.join([ZWC_SPACE if b == '0' else ZWC_JOINER for b in hidden_bits])

        new_data = original_data + hidden_data

        save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if save_path:
            with open(save_path, 'w', encoding='utf-8') as f:
                f.write(new_data)
            messagebox.showinfo("Success", "File Encoded & Saved Successfully!")

    def decode_text_file(self):
        ZWC_SPACE = '\u200B'
        ZWC_JOINER = '\u200C'

        with open(self.file_path, 'r', encoding='utf-8') as f:
            data = f.read()

        hidden_part = ''.join(ch for ch in data if ch in (ZWC_SPACE, ZWC_JOINER))
        hidden_bits = ''.join(['0' if ch == ZWC_SPACE else '1' for ch in hidden_part])

        padding = 8 - (len(hidden_bits) % 8) if len(hidden_bits) % 8 != 0 else 0
        hidden_bits = hidden_bits + '0' * padding

        bytes_list = [chr(int(hidden_bits[i:i + 8], 2)) for i in range(0, len(hidden_bits), 8)]
        combined = ''.join(bytes_list)

        try:
            decoded = base64.b64decode(combined.encode())
            nonce, tag, ciphertext = decoded[:16], decoded[16:32], decoded[32:]
            cipher = AES.new(self.pass_entry.get().encode('utf-8').ljust(32, b'0'), AES.MODE_EAX, nonce=nonce)
            secret = cipher.decrypt_and_verify(ciphertext, tag)
            messagebox.showinfo("Secret Message", f"Secret Message: {secret.decode()}")
        except Exception:
            messagebox.showerror("Error", "Failed to decode or incorrect password!")

    # ===============================
    # IMAGE STEGANOGRAPHY (FAST APPEND)
    # ===============================
    def encode_image_file(self):
        secret_msg = self.msg_entry.get()
        password = self.pass_entry.get()
        if not self.file_path or not secret_msg or not password:
            messagebox.showerror("Error", "All fields are required!")
            return

        cipher = AES.new(password.encode('utf-8').ljust(32, b'0'), AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(secret_msg.encode())
        result = base64.b64encode(cipher.nonce + tag + ciphertext)

        with open(self.file_path, "rb") as file:
            image_data = file.read()

        combined_data = image_data + b":::" + result

        save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Files", "*.png"), ("JPEG Files", "*.jpg;*.jpeg")])
        if save_path:
            with open(save_path, "wb") as file:
                file.write(combined_data)
            messagebox.showinfo("Success", "Image Encoded & Saved Successfully!")

    def decode_image_file(self):
        password = self.pass_entry.get()
        if not self.file_path or not password:
            messagebox.showerror("Error", "All fields are required!")
            return

        try:
            with open(self.file_path, "rb") as file:
                combined_data = file.read()

            if b":::" not in combined_data:
                messagebox.showerror("Error", "No hidden data found!")
                return

            image_data, encrypted_message = combined_data.rsplit(b":::", 1)
            decoded = base64.b64decode(encrypted_message)
            nonce, tag, ciphertext = decoded[:16], decoded[16:32], decoded[32:]
            cipher = AES.new(password.encode('utf-8').ljust(32, b'0'), AES.MODE_EAX, nonce=nonce)
            secret = cipher.decrypt_and_verify(ciphertext, tag)
            messagebox.showinfo("Secret Message", f"Secret Message: {secret.decode()}")
        except Exception:
            messagebox.showerror("Error", "Failed to decode or incorrect password!")

    # ===============================
    # AUDIO STEGANOGRAPHY
    # ===============================
    def encode_audio_file(self):
        if not self.file_path or not self.msg_entry.get() or not self.pass_entry.get():
            messagebox.showerror("Error", "All fields are required!")
            return

        secret_msg = self.msg_entry.get()
        password = self.pass_entry.get()
        cipher = AES.new(password.encode('utf-8').ljust(32, b'0'), AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(secret_msg.encode())
        result = base64.b64encode(cipher.nonce + tag + ciphertext).decode()

        with wave.open(self.file_path, 'rb') as wav_file:
            params = wav_file.getparams()
            frames = wav_file.readframes(params.nframes)

        audio_data = np.frombuffer(frames, dtype=np.int16)
        audio_data = audio_data.copy()

        hidden_bits = ''.join(format(byte, '08b') for byte in result.encode())
        if len(hidden_bits) > len(audio_data):
            messagebox.showerror("Error", "Audio file too small for this message!")
            return

        for i in range(len(hidden_bits)):
            audio_data[i] = (audio_data[i] & ~1) | int(hidden_bits[i])

        save_path = filedialog.asksaveasfilename(defaultextension=".wav", filetypes=[("WAV Files", "*.wav")])
        if save_path:
            with wave.open(save_path, 'wb') as output_wav:
                output_wav.setparams(params)
                output_wav.writeframes(audio_data.tobytes())
            messagebox.showinfo("Success", "Audio Encoded & Saved Successfully!")

    def decode_audio_file(self):
        if not self.file_path or not self.pass_entry.get():
            messagebox.showerror("Error", "All fields are required!")
            return

        password = self.pass_entry.get()

        with wave.open(self.file_path, 'rb') as wav_file:
            params = wav_file.getparams()
            frames = wav_file.readframes(params.nframes)

        audio_data = np.frombuffer(frames, dtype=np.int16)

        hidden_bits = ''.join(str(audio_data[i] & 1) for i in range(len(audio_data)))
        hidden_bytes = bytearray()
        for i in range(0, len(hidden_bits), 8):
            byte = hidden_bits[i:i + 8]
            if len(byte) == 8:
                hidden_bytes.append(int(byte, 2))

        try:
            decoded = base64.b64decode(hidden_bytes)
            nonce, tag, ciphertext = decoded[:16], decoded[16:32], decoded[32:]
            cipher = AES.new(password.encode('utf-8').ljust(32, b'0'), AES.MODE_EAX, nonce=nonce)
            secret = cipher.decrypt_and_verify(ciphertext, tag)
            messagebox.showinfo("Secret Message", f"Secret Message: {secret.decode()}")
        except Exception:
            messagebox.showerror("Error", "Failed to decode or incorrect password!")

    # ===============================
    # VIDEO STEGANOGRAPHY
    # ===============================
    def encode_video_file(self):
        secret_msg = self.msg_entry.get()
        password = self.pass_entry.get()
        if not self.file_path or not secret_msg or not password:
            messagebox.showerror("Error", "All fields are required!")
            return

        cipher = AES.new(password.encode('utf-8').ljust(32, b'0'), AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(secret_msg.encode())
        result = base64.b64encode(cipher.nonce + tag + ciphertext)

        with open(self.file_path, "rb") as file:
            video_data = file.read()

        # Default extension .avi
        save_path = filedialog.asksaveasfilename(defaultextension=".avi", filetypes=[("AVI Files", "*.avi"), ("MP4 Files", "*.mp4")])
        combined_data = video_data + b":::" + result
        if save_path:
            with open(save_path, "wb") as file:
                file.write(combined_data)
            messagebox.showinfo("Success", "Video Encoded & Saved Successfully!")

    def decode_video_file(self):
        password = self.pass_entry.get()
        if not self.file_path or not password:
            messagebox.showerror("Error", "All fields are required!")
            return

        try:
            with open(self.file_path, "rb") as file:
                combined_data = file.read()

            if b":::" not in combined_data:
                messagebox.showerror("Error", "No hidden data found!")
                return

            video_data, encrypted_message = combined_data.rsplit(b":::", 1)
            decoded = base64.b64decode(encrypted_message)
            nonce, tag, ciphertext = decoded[:16], decoded[16:32], decoded[32:]
            cipher = AES.new(password.encode('utf-8').ljust(32, b'0'), AES.MODE_EAX, nonce=nonce)
            secret = cipher.decrypt_and_verify(ciphertext, tag)
            messagebox.showinfo("Secret Message", f"Secret Message: {secret.decode()}")
        except Exception:
            messagebox.showerror("Error", "Failed to decode or incorrect password!")

if __name__ == "__main__":
    app = HideStreamApp()
    app.mainloop()