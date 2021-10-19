#!/usr/bin/env python3

from aes_mode import AESImplementation, AESMode
from config import Config
from node import Node

import socket


class nodeB(Node):
    def __init__(self, key_prime: bytes, iv: bytes) -> None:
        super().__init__(key_prime, iv)
        self._socket = None
        self._connection = None 
    
    def start_connection_with_A(self) -> None:
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.bind((Config.HOST, Config.PORT_A_B))
        self._socket.listen()

        self._connection, _ = self._socket.accept()
        print('Start communicating with A...')
    
    def receive_aes_mode_and_key_from_B(self) -> None:
        aes_mode = self.receive_from_B()
        self._aes_mode = AESMode.ECB \
            if aes_mode == b'ECB' \
            else AESMode.OFB        
        self._encrypted_key = self.receive_from_B()
    
    def receive_file_content_from_A(self) -> None:
        self._connection.sendall(b'Confirmation message')
        encrypted_content = self.receive_from_B()

        AESImpl = AESImplementation(self._aes_mode, self._key, self._iv)
        decrypted_content = AESImpl.decrypt(encrypted_content)

        print(f'File content: \n{"-" * 30}\n{decrypted_content}\n{"-" * 30}')
    
    def receive_from_B(self):
        length = int(self._connection.recv(4).decode())
        return self._connection.recv(length)
    
    def stop_connection_with_A(self) -> None:
        self._socket.close()
        self._connection.close()
        print('Stop communicating with A...')


if __name__ == '__main__':
    print('--- Node B ---')

    B = nodeB(Config.K_PRIME, Config.IV)

    B.start_connection_with_A()

    B.receive_aes_mode_and_key_from_B()
    B.decrypt_key()
    B.receive_file_content_from_A()

    B.stop_connection_with_A()
