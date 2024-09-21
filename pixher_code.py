from PIL import Image
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import zlib
import os
import hashlib
import getpass
import struct
import uuid

# AES settings
BLOCK_SIZE = 16  # AES block size in bytes
KEY_SIZE = 16  # AES-128 uses a 16-byte key (16 bytes = 128 bits)

# Hash password input
def password_input(prompt):
    password = getpass.getpass(prompt)
    hash_object = hashlib.sha512()
    hash_object.update(password.encode('utf-8'))
    hashed_password = hash_object.hexdigest()
    return hashed_password

# Derive key from password using PBKDF2
def derive_key_from_password(password, salt):
    return PBKDF2(password, salt, dkLen=KEY_SIZE, count=len(password) * 9999)

# Encrypt data using AES-GCM
def aes_encrypt(data, password):
    salt = get_random_bytes(32)  # 32 bytes salt
    key = derive_key_from_password(password, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    compressed_data = zlib.compress(data)  # Compress before encryption
    encrypted_data, tag = cipher.encrypt_and_digest(compressed_data)
    return salt + cipher.nonce + tag + encrypted_data

# Decrypt data using AES-GCM
def aes_decrypt(data, password):
    salt = data[:32]
    nonce = data[32:48]
    tag = data[48:64]
    encrypted_data = data[64:]
    key = derive_key_from_password(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decompressed_data = zlib.decompress(cipher.decrypt_and_verify(encrypted_data, tag))  # Decompress after decryption
    return decompressed_data

# Function to convert a file to PNG with AES encryption and save the filename
def file_to_png_with_aes(input_file, password):
    output_image = f"{uuid.uuid4()}.png"
    original_filename = os.path.basename(input_file).encode('utf-8')
    with open(input_file, 'rb') as f:
        data = f.read()

    # Prepend the original filename (with length) to the data
    filename_len = struct.pack('I', len(original_filename))
    data_with_filename = filename_len + original_filename + data
    
    encrypted_data = aes_encrypt(data_with_filename, password)
    data_len = len(encrypted_data)
    img_size = int((data_len / 3) ** 0.5) + 1  # 3 bytes per pixel (RGB)
    image = Image.new('RGB', (img_size, img_size))
    pixels = [(encrypted_data[i], encrypted_data[i+1] if i+1 < len(encrypted_data) else 0, encrypted_data[i+2] if i+2 < len(encrypted_data) else 0) for i in range(0, len(encrypted_data), 3)]
    image.putdata(pixels)
    image.save(output_image)
    # print(f"File encrypted and encoded into PNG image: {output_image}")
    return output_image

# Function to decode the PNG image, extract the original filename, and decrypt it back
def png_to_file_with_aes(input_image, password):
    image = Image.open(input_image)
    pixels = list(image.getdata())
    encrypted_data = bytearray()
    for pixel in pixels:
        encrypted_data.extend(pixel)

    encrypted_data = encrypted_data.rstrip(b'\x00')

    try:
        decrypted_data = aes_decrypt(encrypted_data, password)
        # Extract the original filename
        filename_len = struct.unpack('I', decrypted_data[:4])[0]
        original_filename = "_" + decrypted_data[4:4 + filename_len].decode('utf-8')
        file_data = decrypted_data[4 + filename_len:]

        with open(original_filename, 'wb') as f:
            f.write(file_data)
        # print(f"PNG decoded and decrypted back to file: {original_filename}")
    except (ValueError, zlib.error):
        pass
        # print("Decryption failed. Writing garbage data.")
    
    return original_filename

# # Example usage
# if __name__ == "__main__":
#     # password = password_input("Enter a strong password: ")
#     # confirm_password = password_input("Confirm password: ")

#     # if password != confirm_password:
#     #     print("Passwords do not match.")
#     #     exit()

#     # file_to_png_with_aes('example.pdf', password)

#     password = password_input("Enter the password for decryption: ")
#     png_to_file_with_aes('b0e8a87e-10d0-4d46-9d7b-9f173dd4e7e4.png', password)
