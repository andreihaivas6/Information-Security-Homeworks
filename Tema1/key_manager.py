#!/usr/bin/env python3

from key_generator import KeyGenerator
from my_crypto import MyCrypto
from config import Config

import socket


class KeyManager:
    def __init__(self, key_prime: bytes) -> None:
        self._key_prime = key_prime
    
    def start_server(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
            my_socket.bind((Config.HOST, Config.PORT_A_KM))
            my_socket.listen()
            connection, _ = my_socket.accept()

            print('Start communicating with node A...')
            with connection:
                connection.recv(2048)
                key = self.get_encrypted_key()
                connection.sendall(key)
            print('Stop communicating with node A.')

    def get_encrypted_key(self) -> bytes:
        key = KeyGenerator.get_key()
        print(f'Generated key K: \n{key}')

        return MyCrypto.encrypt(key, self._key_prime)


if __name__ == '__main__':
    print('--- Key Manager ---')

    key_manager = KeyManager(Config.K_PRIME)
    key_manager.start_server()
