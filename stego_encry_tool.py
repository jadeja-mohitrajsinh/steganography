from PIL import Image
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64
import getpass

# Helper function to generate a key from a password and salt
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Encrypt the plaintext using AES
def encrypt(plaintext: str, password: str) -> str:
    salt = os.urandom(16)  # Generate a random salt
    key = derive_key(password, salt)
    iv = os.urandom(16)  # Generate a random initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padded_plaintext = plaintext + (16 - len(plaintext) % 16) * chr(16 - len(plaintext) % 16)  # PKCS7 padding
    encrypted = encryptor.update(padded_plaintext.encode()) + encryptor.finalize()
    return base64.b64encode(salt + iv + encrypted).decode()

# Decrypt the ciphertext using AES
def decrypt(ciphertext: str, password: str) -> str:
    data = base64.b64decode(ciphertext)
    salt = data[:16]
    iv = data[16:32]
    encrypted = data[32:]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(encrypted) + decryptor.finalize()
    padding_len = padded_plaintext[-1]
    return padded_plaintext[:-padding_len].decode()

# Function to encode a message into an image using LSB steganography
def encode_image(image_path: str, message: str, output_path: str):
    img = Image.open(image_path)
    img = img.convert("RGB")
    encoded_image = img.copy()
    pixels = encoded_image.load()

    message = message + chr(0)  # Adding a delimiter
    binary_message = ''.join(format(ord(c), '08b') for c in message)
    binary_message += '00000000'  # End-of-message delimiter

    if len(binary_message) > img.size[0] * img.size[1] * 3:
        raise ValueError("Message is too large to encode in the image")

    data_index = 0
    for y in range(img.size[1]):
        for x in range(img.size[0]):
            pixel = list(pixels[x, y])
            for n in range(3):
                if data_index < len(binary_message):
                    pixel[n] = (pixel[n] & ~1) | int(binary_message[data_index])
                    data_index += 1
            pixels[x, y] = tuple(pixel)

    encoded_image.save(output_path)
    print(f"Message encoded into {output_path}")

# Function to decode a message from an image
def decode_image(image_path: str) -> str:
    img = Image.open(image_path)
    img = img.convert("RGB")
    pixels = img.load()

    binary_message = ''
    for y in range(img.size[1]):
        for x in range(img.size[0]):
            pixel = list(pixels[x, y])
            for n in range(3):
                binary_message += str(pixel[n] & 1)

    binary_message = [binary_message[i:i + 8] for i in range(0, len(binary_message), 8)]
    decoded_message = ''
    for byte in binary_message:
        decoded_char = chr(int(byte, 2))
        if decoded_char == chr(0):  # End-of-message delimiter
            break
        decoded_message += decoded_char

    return decoded_message

# Main function to handle user input and process encryption, encoding, decoding, and decryption
def main():
    while True:
        print("Select an option:")
        print("1. Encrypt and encode message")
        print("2. Decode and decrypt message")
        print("3. Exit")

        choice = input("Enter your choice (1/2/3): ")

        if choice == '1':
            # Encrypt and encode message
            password = getpass.getpass("Enter password for encryption: ")
            original_message = input("Enter the message to encrypt: ")
            image_path = input("Enter the path to the input image: ")
            encoded_image_path = input("Enter the path to save the encoded image: ")

            # Encrypt the message
            encrypted_message = encrypt(original_message, password)
            print("Encrypted Message:", encrypted_message)

            # Encode the encrypted message into the image
            encode_image(image_path, encrypted_message, encoded_image_path)

        elif choice == '2':
            # Decode and decrypt message
            password = getpass.getpass("Enter password for decryption: ")
            encoded_image_path = input("Enter the path to the encoded image: ")

            # Decode the message from the image
            decoded_encrypted_message = decode_image(encoded_image_path)
            print("Decoded Encrypted Message:", decoded_encrypted_message)

            # Decrypt the message
            decrypted_message = decrypt(decoded_encrypted_message, password)
            print("Decrypted Message:", decrypted_message)

        elif choice == '3':
            # Exit
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please select 1, 2, or 3.")

if __name__ == "__main__":
    main()
