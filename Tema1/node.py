from aes_mode import AESMode
from my_crypto import MyCrypto


class Node:
    def __init__(self, key_prime: bytes, iv: bytes) -> None:
        self._key_prime = key_prime
        self._iv = iv
        self._encrypted_key = b''
        self._key = b''
        self._aes_mode: AESMode = None

    def decrypt_key(self) -> None:
        self._key = MyCrypto.decrypt(self._encrypted_key, self._key_prime)
        print(f'Key K after decrypting:\n{self._key}')

    @property
    def aes_mode(self) -> AESMode:
        return self._aes_mode
    
    @aes_mode.setter
    def aes_mode(self, aes_mode: AESMode) -> None:
        self._aes_mode = aes_mode

    def __str__(self) -> str:
        return f'Node:\nkey: {self._key}\nAES_Mode: {self._aes_mode.value}\n'