"""
all cryptographic functions for the WALA application:
- RSA key generation and management
- DES encryption/decryption with CBC mode
- Digital signatures using RSA
- Session key exchange using RSA-OAEP
- Password hashing with bcrypt
"""

import os
import base64
import bcrypt
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import config


class CryptoError(Exception):
    pass


def generate_rsa_keypair(key_size=config.RSA_KEY_SIZE):
    try:
        private_key = RSA.generate(key_size)
        public_key = private_key.publickey()
        return private_key, public_key
    except Exception as e:
        raise CryptoError(f"Failed to generate RSA key pair: {e}")


def export_public_key(public_key):
    try:
        return public_key.export_key(format='PEM')
    except Exception as e:
        raise CryptoError(f"Failed to export public key: {e}")


def import_public_key(pem_data):
    try:
        return RSA.import_key(pem_data)
    except Exception as e:
        raise CryptoError(f"Failed to import public key: {e}")


def generate_session_key():
    return get_random_bytes(config.DES_KEY_SIZE)


def encrypt_session_key(session_key, recipient_public_key):
    try:
        cipher_rsa = PKCS1_OAEP.new(recipient_public_key)
        encrypted_key = cipher_rsa.encrypt(session_key)
        return encrypted_key
    except Exception as e:
        raise CryptoError(f"Failed to encrypt session key: {e}")


def decrypt_session_key(encrypted_key, recipient_private_key):
    try:
        cipher_rsa = PKCS1_OAEP.new(recipient_private_key)
        session_key = cipher_rsa.decrypt(encrypted_key)
        return session_key
    except Exception as e:
        raise CryptoError(f"Failed to decrypt session key: {e}")


def encrypt_message(plaintext, session_key):
    try:
        plaintext_bytes = plaintext.encode('utf-8')
        cipher = DES.new(session_key, DES.MODE_CBC)
        padded_plaintext = pad(plaintext_bytes, config.DES_BLOCK_SIZE)
        ciphertext = cipher.encrypt(padded_plaintext)
        return cipher.iv + ciphertext
    except Exception as e:
        raise CryptoError(f"Failed to encrypt message: {e}")


def decrypt_message(encrypted_data, session_key):
    try:
        iv = encrypted_data[:config.DES_BLOCK_SIZE]
        ciphertext = encrypted_data[config.DES_BLOCK_SIZE:]
        cipher = DES.new(session_key, DES.MODE_CBC, iv=iv)
        padded_plaintext = cipher.decrypt(ciphertext)
        plaintext_bytes = unpad(padded_plaintext, config.DES_BLOCK_SIZE)
        return plaintext_bytes.decode('utf-8')
    except Exception as e:
        raise CryptoError(f"Failed to decrypt message: {e}")


def sign_message(message, private_key):
    try:
        if isinstance(message, str):
            message = message.encode('utf-8')
        hash_obj = SHA256.new(message)
        signature = pkcs1_15.new(private_key).sign(hash_obj)
        return signature
    except Exception as e:
        raise CryptoError(f"Failed to sign message: {e}")


def verify_signature(message, signature, public_key):
    try:
        if isinstance(message, str):
            message = message.encode('utf-8')
        hash_obj = SHA256.new(message)
        pkcs1_15.new(public_key).verify(hash_obj, signature)
        return True
    except (ValueError, TypeError):
        return False
    except Exception as e:
        raise CryptoError(f"Failed to verify signature: {e}")


def hash_password(password):
    try:
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed
    except Exception as e:
        raise CryptoError(f"Failed to hash password: {e}")


def verify_password(password, hashed):
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed)
    except Exception as e:
        raise CryptoError(f"Failed to verify password: {e}")


def encode_base64(data):
    return base64.b64encode(data).decode('utf-8')


def decode_base64(data):
    try:
        return base64.b64decode(data.encode('utf-8'))
    except Exception as e:
        raise CryptoError(f"Failed to decode base64 data: {e}")