from my_crypto import MyCrypto

from enum import Enum


class AESMode(Enum):
    ECB = "ECB"
    OFB = "OFB"


class AESImplementation:
    BLOCK_SIZE = 16
    BLOCK_SIZE_FOR_DECRYPT = 2 * BLOCK_SIZE
    PADDING_CHARACTER = bytes([0])

    def __init__(self, mode: AESMode, key: bytes, iv: bytes) -> None:
        self._mode = mode 
        self._key = key
        self._iv = iv
    
    def encrypt(self, message_to_crypt: str) -> bytes:
        print('Encrypting message...')
        return self._encrypt_ecb(message_to_crypt) \
            if self._mode == AESMode.ECB \
            else self._encrypt_ofb(message_to_crypt)

    def decrypt(self, message_to_decrypt: bytes) -> str:
        print('Decrypting message...')
        return self._decrypt_ecb(message_to_decrypt) \
            if self._mode == AESMode.ECB \
            else self._decrypt_ofb(message_to_decrypt)
    
    def my_pad(self, text: bytes) -> bytes:
        return text + self.PADDING_CHARACTER * (self.BLOCK_SIZE - len(text))
    
    def my_unpad(self, text: str) -> str:
        first_pos = text.find(self.PADDING_CHARACTER.decode())
        if first_pos != -1:
            return text[:first_pos]
    
    def _encrypt_ecb(self, message_to_crypt: str) -> bytes:
        message_to_crypt = message_to_crypt.encode()
        plaintext_list = [
            message_to_crypt[i: i + self.BLOCK_SIZE]
            for i in range(0, len(message_to_crypt), self.BLOCK_SIZE)
        ]
        plaintext_list[-1] = self.my_pad(plaintext_list[-1])

        ciphertext_list = [
            MyCrypto.encrypt(plaintext, self._key)
            for plaintext in plaintext_list
        ]

        return b''.join(ciphertext_list)

    def _decrypt_ecb(self, message_to_decrypt: bytes) -> str:
        ciphertext_list = [
            message_to_decrypt[i: i + self.BLOCK_SIZE_FOR_DECRYPT]
            for i in range(0, len(message_to_decrypt), self.BLOCK_SIZE_FOR_DECRYPT)
        ]

        plaintext_list = [
            MyCrypto.decrypt_with_decode(ciphertext, self._key)
            for ciphertext in ciphertext_list
        ]
        plaintext_list[-1] = self.my_unpad(plaintext_list[-1])

        return ''.join(plaintext_list)

    def xor(self, bytes1: bytes, bytes2: bytes) -> bytes:
        return bytes([
            x ^ y 
            for x, y in zip(bytes1, bytes2)
        ])

    def _encrypt_ofb(self, message_to_crypt: str) -> bytes:
        message_to_crypt = message_to_crypt.encode()
        plaintext_list = [
            message_to_crypt[i: i + self.BLOCK_SIZE]
            for i in range(0, len(message_to_crypt), self.BLOCK_SIZE)
        ]
        plaintext_list[-1] = self.my_pad(plaintext_list[-1])

        ciphertext_list = list()
        block_cipher = self._iv

        for plaintext in plaintext_list:
            block_cipher = MyCrypto.encrypt(block_cipher, self._key)
            ciphertext = self.xor(block_cipher, plaintext)
            ciphertext_list.append(ciphertext)

        return b''.join(ciphertext_list)
    
    def _decrypt_ofb(self, message_to_decrypt: bytes) -> str:
        ciphertext_list = [
            message_to_decrypt[i: i + self.BLOCK_SIZE]
            for i in range(0, len(message_to_decrypt), self.BLOCK_SIZE)
        ]

        plaintext_list = list()
        block_cipher = self._iv

        for index, ciphertext in enumerate(ciphertext_list):
            block_cipher = MyCrypto.encrypt(block_cipher, self._key)
            plaintext = self.xor(block_cipher, ciphertext).decode()
            
            if index == len(ciphertext_list) - 1:
                plaintext = self.my_unpad(plaintext)
            plaintext_list.append(plaintext)

        return ''.join(plaintext_list)

