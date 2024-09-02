import base64
from PIL import Image
from pyKCS11 import PyKCS11Lib, CKA_ID

# Define the path to your PKCS#11 library
PKCS11_LIB_PATH = '/path/to/your/pkcs11/library'

# Initialize the PKCS#11 library
pkcs11 = PyKCS11Lib()
pkcs11.load(PKCS11_LIB_PATH)

def encrypt_message(message: str, key_id: str) -> str:
    try:
        session = pkcs11.openSession(0)
        key = session.findObjects([(CKA_ID, key_id)])[0]
        encrypted = session.encrypt(key, message.encode())
        session.closeSession()
        return base64.b64encode(encrypted).decode()
    except Exception as e:
        print(f"Error during encryption: {e}")
        return None

def decrypt_message(encrypted_message: str, key_id: str) -> str:
    try:
        encrypted = base64.b64decode(encrypted_message)
        session = pkcs11.openSession(0)
        key = session.findObjects([(CKA_ID, key_id)])[0]
        decrypted = session.decrypt(key, encrypted)
        session.closeSession()
        return decrypted.decode()
    except Exception as e:
        print(f"Error during decryption: {e}")
        return None

def encode_image(image_path: str, message: str, output_path: str):
    try:
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
    except Exception as e:
        print(f"Error during encoding: {e}")

def decode_image(image_path: str) -> str:
    try:
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
    except Exception as e:
        print(f"Error during decoding: {e}")
        return None
