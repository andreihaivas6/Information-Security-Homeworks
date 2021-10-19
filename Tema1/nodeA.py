#!/usr/bin/env python3

from config import Config
from node import Node
from aes_mode import AESMode, AESImplementation

import socket


class nodeA(Node):
    def __init__(self, key_prime: bytes, iv: bytes) -> None:
        super().__init__(key_prime, iv)
        self._connection = None

    def get_encrypted_key_from_key_manager(self) -> bytes:
        print('Start communicating with Key Manager...')

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
            my_socket.connect((Config.HOST, Config.PORT_A_KM))
            my_socket.sendall(b'Give me the key K!')

            self._encrypted_key = my_socket.recv(2048)

            print('Received encrypted key K from Key Manager.')
            return self._encrypted_key
    
    def start_connection_with_B(self) -> None:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        my_socket.connect((Config.HOST, Config.PORT_A_B))

        self._connection = my_socket
        print('Start communicating with B...')
    
    def send_aes_mode_and_key_to_B(self) -> None:
        line = input('Choose AES Mode: \n1. ECB\n2. OFB\n')
        self._aes_mode = AESMode.ECB \
            if line == '1' \
            else AESMode.OFB

        self.send_to_B(self._aes_mode.value)
        self.send_to_B(self._encrypted_key)
    
    def send_file_content_to_B(self) -> None:
        self._connection.recv(20)
        with open(Config.FILENAME, 'r') as file_object:
            content = file_object.read()
            
            AES_impl = AESImplementation(self._aes_mode, self._key, self._iv)
            crypted_content = AES_impl.encrypt(content)
            self.send_to_B(crypted_content)
    
    def send_to_B(self, msg) -> None:
        """
        trimitem si lungimea mesajului ca sa stim cat avem de citit
        numarul il trimitem ca un sir de 4 caractere (si adaugam spatii pana la 4)
        2   -> '2   '
        150 -> '150 '
        """
        if not isinstance(msg, bytes):
            msg = msg.encode()
        length = str(len(msg)) + ' ' * (4 - len(str(len(msg))))

        self._connection.send(length.encode())
        self._connection.send(msg)

    def stop_connection_with_B(self) -> None:
        self._connection.close()
        print('Stop communicating with B...')


if __name__ == '__main__':
    print('--- Node A ---')

    A = nodeA(Config.K_PRIME, Config.IV)
    A.get_encrypted_key_from_key_manager()

    A.start_connection_with_B()

    A.send_aes_mode_and_key_to_B()
    A.decrypt_key()
    A.send_file_content_to_B()

    A.stop_connection_with_B()
