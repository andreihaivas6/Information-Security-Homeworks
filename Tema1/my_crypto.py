from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class MyCrypto:
    PAD_NUMBER_OF_BITS = 16
    
    @staticmethod
    def encrypt(message_to_crypt, key: bytes) -> bytes:
        cipher = AES.new(key, AES.MODE_ECB)

        if not isinstance(message_to_crypt, bytes):
            message_to_crypt = message_to_crypt.encode()
        message_to_crypt = pad(message_to_crypt, MyCrypto.PAD_NUMBER_OF_BITS)
        message_encrypted = cipher.encrypt(message_to_crypt)

        return message_encrypted

    @staticmethod
    def decrypt(message_to_decrypt: bytes, key: bytes) -> bytes:
        decipher = AES.new(key, AES.MODE_ECB)

        message_decrypted = decipher.decrypt(message_to_decrypt)
        message_decrypted = unpad(message_decrypted, MyCrypto.PAD_NUMBER_OF_BITS)

        return message_decrypted
    
    @staticmethod
    def decrypt_with_decode(message_to_decrypt: bytes, key: bytes) -> str:
        return MyCrypto.decrypt(message_to_decrypt, key).decode()
