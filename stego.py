# stego.py - LSB Steganography Module
# Course: 605346 - Information & Network Security Programming
# University of Petra
#
# Hides a secret text message inside a PNG image using LSB (Least Significant Bit)
# steganography. Optionally encrypts the message with AES before hiding it.
#
# Usage:
#   python stego.py hide   input.png output.png "your secret message"
#   python stego.py extract output.png
#   python stego.py hide-enc   input.png output.png "secret" "password"
#   python stego.py extract-enc output.png "password"

import sys
import os
from PIL import Image

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Hash import SHA256
    CRYPTO_OK = True
except:
    CRYPTO_OK = False

DELIMITER = "##END##"


def make_key(password):
    h = SHA256.new()
    h.update(password.encode())
    return h.digest()


def aes_encrypt(text, password):
    key = make_key(password)
    cipher = AES.new(key, AES.MODE_CBC)
    ct = cipher.encrypt(pad(text.encode(), AES.block_size))
    return (cipher.iv + ct).hex()


def aes_decrypt(hex_data, password):
    key = make_key(password)
    raw = bytes.fromhex(hex_data)
    iv = raw[:16]
    ct = raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size).decode()


def text_to_bits(text):
    bits = ""
    for ch in text:
        bits += format(ord(ch), "08b")
    return bits


def bits_to_text(bits):
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) < 8:
            break
        chars.append(chr(int(byte, 2)))
    return "".join(chars)


def hide(input_path, output_path, message):
    img = Image.open(input_path).convert("RGB")
    pixels = list(img.getdata())
    width, height = img.size

    full_msg = message + DELIMITER
    bits = text_to_bits(full_msg)

    max_bits = len(pixels) * 3
    if len(bits) > max_bits:
        print(f"[!] Message too long. Max: {max_bits // 8} chars, got {len(full_msg)}")
        return

    new_pixels = []
    bit_idx = 0

    for pixel in pixels:
        r, g, b = pixel
        channels = [r, g, b]
        new_channels = []
        for ch in channels:
            if bit_idx < len(bits):
                ch = (ch & 0xFE) | int(bits[bit_idx])
                bit_idx += 1
            new_channels.append(ch)
        new_pixels.append(tuple(new_channels))

    out_img = Image.new("RGB", (width, height))
    out_img.putdata(new_pixels)
    out_img.save(output_path)

    print(f"[+] Message hidden in: {output_path}")
    print(f"[+] Message length: {len(message)} chars | Bits used: {len(bits)}/{max_bits}")


def extract(image_path):
    img = Image.open(image_path).convert("RGB")
    pixels = list(img.getdata())

    bits = ""
    for pixel in pixels:
        for ch in pixel:
            bits += str(ch & 1)

    text = bits_to_text(bits)
    if DELIMITER in text:
        msg = text.split(DELIMITER)[0]
        print(f"[+] Extracted message:\n    {msg}")
        return msg
    else:
        print("[!] No hidden message found or image is not a stego image.")
        return None


mode = sys.argv[1] if len(sys.argv) > 1 else "help"

if mode == "hide":
    if len(sys.argv) < 5:
        print("Usage: python stego.py hide input.png output.png \"message\"")
    else:
        hide(sys.argv[2], sys.argv[3], sys.argv[4])

elif mode == "extract":
    if len(sys.argv) < 3:
        print("Usage: python stego.py extract image.png")
    else:
        extract(sys.argv[2])

elif mode == "hide-enc":
    if not CRYPTO_OK:
        print("[!] pycryptodome not installed. Run: pip install pycryptodome")
    elif len(sys.argv) < 6:
        print("Usage: python stego.py hide-enc input.png output.png \"message\" \"password\"")
    else:
        encrypted = aes_encrypt(sys.argv[4], sys.argv[5])
        hide(sys.argv[2], sys.argv[3], encrypted)
        print("[+] Message was AES-encrypted before hiding.")

elif mode == "extract-enc":
    if not CRYPTO_OK:
        print("[!] pycryptodome not installed.")
    elif len(sys.argv) < 4:
        print("Usage: python stego.py extract-enc image.png \"password\"")
    else:
        raw = extract(sys.argv[2])
        if raw:
            try:
                plaintext = aes_decrypt(raw, sys.argv[3])
                print(f"[+] Decrypted message:\n    {plaintext}")
            except Exception as e:
                print(f"[!] Decryption failed: {e}")

else:
    print("\nUsage:")
    print("  python stego.py hide input.png output.png \"secret message\"")
    print("  python stego.py extract output.png")
    print("  python stego.py hide-enc input.png output.png \"secret\" \"password\"")
    print("  python stego.py extract-enc output.png \"password\"")
    print("\nInstall: pip install pillow pycryptodome")
