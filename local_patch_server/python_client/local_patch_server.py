import traceback
from libraries.connection import Connection
from libraries.message import Message
from libraries.socketconnector import SocketConnector
from libraries.codesys import Codesys
from libraries.utils import *
from libraries.constants import *

def main():
    remoteConnector = SocketConnector()
    codesysConnector = Codesys()
    lkmConnector = Connection(nlservice=NETLINK_USER)
    remoteConnector.initialize_server()
    _codesysPID = ''

    try:
        while True:
            print('[*] Waiting for a connection')
            connection, client_address = remoteConnector.socketConnection.accept()
            print('[*] Connection from: {}'.format(client_address))
            while True:
                data = connection.recv(1024)
                if data:
                    _message = remoteConnector.parse_message(data)
                    _command, _address, _payload = remoteConnector.process_command(_message)
                    print('\n[*] Received data: Command({}) Address({}) Payload({})'.format(_command, _address, _payload))

                    if _command == COMM_QUIT:
                        print('[*] Received quit command, closing connection')
                        connection.close()
                        break

                    if _command == LOCATE_ADDRESSES:
                        _codesysPID, _mainTaskStartAddress, _mainTaskMapEndAddress = codesysConnector.get_inmemory_addresses()
                        print('- Codesys Information PID: {}, Main Task Start Address: {}, Main Task End Address: {}'.format(hex(_codesysPID), hex(_mainTaskStartAddress), hex(_mainTaskMapEndAddress)))
                        remoteConnector.send_message(connection, {'pid': _codesysPID, 'mainTaskStartAddress': _mainTaskStartAddress, 'mainTaskMapEndAddress': _mainTaskMapEndAddress})

                    if _command == VERIFY_MEMORY_LOCATION or _command == INSTALL_JUMP_ADDRESS or _command == INSTALL_MICRO_PATCH or _command == INSTALL_HOOK:
                        patch_bit_str = hex_str_to_bit_str(_payload)

                        if _command == VERIFY_MEMORY_LOCATION:
                            print('- Destination verification address: {}'.format(hex(_address)))
                            print('- Memory verification payload bit string: {}'.format(patch_bit_str))
                        else:
                            print('- Patch destination address: {}'.format(hex(_address)))
                            print('- Patch bit string: {}'.format(patch_bit_str))

                        message = Message(type=NLMSG_MIN_TYPE, flags=NLM_F_REQUEST, pid=int(_codesysPID), address=_address, payload_len=len(_payload)//2, payload=patch_bit_str, command=_command)
                        print("- Sending payload {} to the LKM Patcher ...".format(message.payload))
                        lkmConnector.send(message)

                        recv_message = lkmConnector.recv()
                        lkm_reply = recv_message.payload.decode('utf-8', errors='strict')
                        print("- LKM Patcher reply: {} ...".format(lkm_reply))

                        if "SUCCESS" in lkm_reply:
                            remoteConnector.send_message(connection, {'status': SUCCESS})
                        elif "FAIL" in lkm_reply:
                            remoteConnector.send_message(connection, {'status': FAILURE})
                        print('- Reply sent to ICSPatch server ...')

    except Exception as err:
        print('[*] Error: {}'.format(err))
        traceback.print_exc()
        remoteConnector.socketConnection.close()

if __name__ == '__main__':
    main()