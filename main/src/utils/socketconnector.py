import os
import sys
import socket
import pickle

import paramiko
from paramiko import SSHClient
from scp import SCPClient

currentDir = os.path.dirname(os.path.realpath(__file__))
parentDir = os.path.dirname(currentDir)
sys.path.append(parentDir)

from utils.constants import *

class SocketConnector:
    def __init__(self, _patcherPreference = C, _targetDevice = BBB):
        self.patcherPreference = _patcherPreference
        self.targetDevice = _targetDevice
        self.socketConnection = None
        self.remoteHost = '192.168.7.2'
        self.remotePort = 49152

    def convert_int_to_binary_str(self, _num, _if16Bit = False):
        if _if16Bit:
            return (16 - len("{0:b}".format(_num)))*'0' + "{0:b}".format(_num)
        return (32 - len("{0:b}".format(_num)))*'0' + "{0:b}".format(_num)

    def hex_str_to_bit_str(self, _hex_str):
        bit_str = ''
        for hex_char in _hex_str:
            bit_str += bin(int(hex_char, 16))[2:].zfill(4)
        return bit_str

    def send_message(self, _command, _address, _payload):
        _message = pickle.dumps({'command': _command, 'address': _address, 'payload': _payload})
        self.socketConnection.send(_message)

    def receive_message(self):
        while True:
            _message = self.socketConnection.recv(1024)
            if _message:
                return pickle.loads(_message)

    def initialize_connection(self):
        try:
            self.socketConnection = socket.socket()
            self.socketConnection.settimeout(10)
            self.socketConnection.connect((self.remoteHost, self.remotePort))

            print('\n[*] Socket connection established')
            print('[*] Remote host: ' + self.remoteHost)
            print('[*] Remote port: ' + str(self.remotePort))
        except Exception as err:
            print('Socket connection failed: {}'.format(err))
            print("Cannot connect to local patch server ... Exiting")
            exit()

    def locate_codesys_inmemory(self, _taskStructAddress = None):
        self.send_message(_command = LOCATE_ADDRESSES, _address = 0, _payload = 0)
        _data = self.receive_message()
        return _data['pid'], _data['mainTaskStartAddress'], _data['mainTaskMapEndAddress']

    def locate_codesys_inmemory_c(self, _taskStructAddress = None):
        _message = self.convert_int_to_binary_str(_num = LOCATE_ADDRESSES, _if16Bit = True) + '0' * 32 + '0' * 32
        print('\n[*] Sending message: ' + _message)
        self.socketConnection.send(_message.encode())

        _data = self.socketConnection.recv(1024).decode()
        if self.targetDevice == BBB:
            return int(_data[0:4], 16), int(_data[4:12], 16), int(_data[12:], 16)
        elif self.targetDevice == WAGO:
            return int(_data[0:4], 16), int(_data[4:12], 16), int(_data[12:20], 16), int(_data[20:28], 16), int(_data[28:], 16)

    def write_in_memory(self, _command, _address, _payload):
        self.send_message(_command = _command, _address = _address, _payload = _payload)
        _data = self.receive_message()
        if _data['status'] == SUCCESS:
            print('- Success message received from the local patch server ...')
        elif _data['status'] == FAILURE:
            print('[X] Failure message received from the local patch server ...')
            sys.exit(0)

    def write_in_memory_c(self, _command, _address, _payload):
        _message = self.convert_int_to_binary_str(_num = _command, _if16Bit = True) + self.convert_int_to_binary_str(_num = _address, _if16Bit = False) + self.hex_str_to_bit_str(_hex_str = _payload)
        print('\n[*] Sending message: ' + _message)
        self.socketConnection.send(_message.encode())

        _data = self.socketConnection.recv(1024).decode()
        if int(_data, 16) == SUCCESS:
            print('- Success message received from the local patch server ...')
        elif int(_data, 16) == FAILURE:
            print('[X] Failure message received from the local patch server ...')
            sys.exit(0)

    def close_connection(self):
        _message = "0000000111111000"
        print('\n[*] Sending message: ' + _message)

        self.socketConnection.send(_message.encode())
        self.socketConnection.close()
        print('[*] Socket connection closed')

    def get_hexdump_with_scp(self, _ip, _port, _username, _password, _remoteFilePath, _localFilePath):
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.load_system_host_keys()
        ssh.connect(hostname = _ip, 
                    port = _port,
                    username = _username,
                    password = _password)

        scp = SCPClient(ssh.get_transport())
        scp.get(_remoteFilePath, _localFilePath)

        scp.close()
        ssh.close()
        
    def remove_file_from_plc(self, _ip, _port, _username, _password, _remoteFilePath):
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.load_system_host_keys()
        ssh.connect(hostname = _ip, 
                    port = _port,
                    username = _username,
                    password = _password)
        
        command = "rm -rf " + _remoteFilePath
        print("- Executing command: " + command)
        (stdin, stdout, stderr) = ssh.exec_command(command)
        for line in stdout.readlines():
            print("OUTPUT: %s".format(line))

        ssh.close()

    def get_memory_page(self, _pid, _startAddress, _endAddress, _dirPath, _pageName):
        size = _endAddress - _startAddress
        _message = self.convert_int_to_binary_str(_num = GET_PROC_MEMORY, _if16Bit = True) + self.convert_int_to_binary_str(_num = _startAddress, _if16Bit = False) + self.convert_int_to_binary_str(_num = size, _if16Bit = False)
        print('\n[*] Sending message: ' + _message)
        self.socketConnection.send(_message.encode())

        _data = self.socketConnection.recv(1024).decode()
        if int(_data, 16) == SUCCESS:
            print('- Success message received from the local patch server ...')

        remote_file_name = '0x' + hex(_startAddress)[2:].zfill(8) + '_code.bin'
        if self.targetDevice == BBB:
            print('- Connecting with BeagleBone Black ...')
            self.get_hexdump_with_scp('192.168.7.2', '22', 'debian', 'temppwd', '/home/debian/' + remote_file_name, os.getcwd() + '/' + _dirPath + '/' + _pageName)
            self.remove_file_from_plc('192.168.7.2', '22', 'debian', 'temppwd', '/home/debian/' + remote_file_name)
        elif self.targetDevice == WAGO:
            print('- Connecting with WAGO ...')
            self.get_hexdump_with_scp('192.168.7.2', '22', 'root', 'wago', '/root/' + remote_file_name, os.getcwd() + '/' + _dirPath + '/' + _pageName)
            self.remove_file_from_plc('192.168.7.2', '22', 'root', 'wago', '/root/' + remote_file_name)

        return _dirPath + '/' + _pageName

    def get_register_values(self, _pc):
        if self.targetDevice == BBB:
            _r0 = 0
            _r1 = 140963940
            _r2 = 75000
            _r3 = 0
            _r4 = _pc + 1
            _r5 = 0
            _r6 = 0 # Can only be calculated after angr is initialized
            _r7 = _pc - 0x12d8
            _r8 = _pc - 0x1280
            _r9 = 1
            _r10 = 0
            _r11 = 139261400
            _r12 = 140389804
            _r13 = _pc - 0x12b8
            _r14 = _pc + 0x1d1
            _flags = 80010030
        elif self.targetDevice == WAGO:
            _r0 = 0
            _r1 = 0
            _r2 = 0
            _r3 = 0
            _r4 = _pc - 0x1228
            _r5 = 0
            _r6 = _pc
            _r7 = 0
            _r8 = 0
            _r9 = 0
            _r10 = _pc - 0x1280
            _r11 = 0
            _r12 = 0
            _r13 = _pc - 0x12a0
            _r14 = _pc + 0x280
            _flags = 80010030
        return [_r0, _r1, _r2, _r3, _r4, _r5, _r6, _r7, _r8, _r9, _r10, _r11, _r12, _r13, _r14, _flags]