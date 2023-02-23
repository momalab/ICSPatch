import sys
import socket
import pickle

from libraries.constants import *

class SocketConnector:
    def __init__(self):
        self.socketConnection = None
        self.remotePort = 49152

    def initialize_server(self):
        try:
            self.socketConnection = socket.socket()
            print('[*] Socket created')
            self.socketConnection.bind(('', self.remotePort))
            print('[*] Socket bind complete')
            self.socketConnection.listen(1)
            print('[*] Socket now listening')
        except Exception as err:
            print('Socket connection failed: {}'.format(err))

    def parse_message(self, _message):
        return pickle.loads(_message)
    
    def send_message(self, _connection, _message):
        _connection.send(pickle.dumps(_message))

    def process_command(self, _message):
        _command = _message['command']
        _address = _message['address']
        _payload = _message['payload']
        return _command, _address, _payload