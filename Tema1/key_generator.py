import secrets

class KeyGenerator:
    NUMBER_OF_BITS = 128

    @staticmethod
    def get_key() -> bytes:
        return secrets.token_bytes(KeyGenerator.NUMBER_OF_BITS // 8)
