import os
import sys
import struct
from pwn import *

currentDir = os.path.dirname(os.path.realpath(__file__))
parentDir = os.path.dirname(currentDir)
sys.path.append(parentDir)

from utils.jtag import Jtag
from utils.socketconnector import SocketConnector
from utils.constants import *

INIT_TASK = 0xc150c340      # For BBB kernel 4.19.82-ti-rt-r31

class CodesysConnector:
    def __init__(self, _operationMode = SOFT_MODE, _targetDevice = BBB, _patcherPreference = C):
        self.operationMode = _operationMode
        self.targetDevice = _targetDevice
        self.patcherPreference = _patcherPreference

        if self.operationMode == JTAG_MODE:
            self.lowLevelConnector = Jtag()
        elif self.operationMode == SOFT_MODE:
            self.lowLevelConnector = SocketConnector(_patcherPreference, _targetDevice)
        
        self.codesysPID = ''
        self.mappedStartAddress = 0
        self.mappedAppAddress = 0
        self.codeCaveAddress = 0
        self.mainTaskMapEndAddress = 0
        self.dataSectionStartAddress = 0
        self.dataSectionEndAddress = 0
        
        # Tracking mapped memory regions
        self.mappedAddressesList = []


    #### HELPER FUNCTIONS ####
    def initialize_connector(self):
        self.lowLevelConnector.initialize_connection()

    def release_jtag_connection(self):
        self.lowLevelConnector.disconnect_lauterbach()

    def close_connection(self):
        self.lowLevelConnector.close_connection()

    def set_break_at_app_start(self):
        self.lowLevelConnector.set_breakpoint(self.codesysPID, self.mappedAppAddress)

    def set_break_at_location(self, _pid, _address):
        self.lowLevelConnector.set_breakpoint(_pid, _address)

    def remove_app_breakpoint(self):
        self.lowLevelConnector.remove_all_breakpoint()

    def check_if_cpu_halted(self):
        return self.lowLevelConnector.check_if_halted()

    def cpu_halt(self):
        self.lowLevelConnector.cpu_break()

    def cpu_go(self):
        self.lowLevelConnector.cpu_go()

    ####

    # Return mapped_memory_start_address, mapped_app_address, code_cave_address
    def get_inmemory_addresses(self):
        # Time
        start = time.time()

        # PYTHON and JTAG
        if self.operationMode == JTAG_MODE or self.patcherPreference == PYTHON:
            self.codesysPID, _mainTaskMapStartAddress, self.mainTaskMapEndAddress = self.lowLevelConnector.locate_codesys_inmemory(INIT_TASK)
        elif self.targetDevice == BBB and self.patcherPreference == C:
            self.codesysPID, _mainTaskMapStartAddress, self.mainTaskMapEndAddress = self.lowLevelConnector.locate_codesys_inmemory_c(INIT_TASK)
        elif self.targetDevice == WAGO and self.patcherPreference == C:
            self.codesysPID, _mainTaskMapStartAddress, self.mainTaskMapEndAddress, _dataSectionStartAddress, _dataSectionEndAddress = self.lowLevelConnector.locate_codesys_inmemory_c(INIT_TASK)

        # Time
        print('[*] Time for locating codesys in memory addresses: ' + str(time.time() - start))

        if self.targetDevice == BBB:
            self.mappedStartAddress = _mainTaskMapStartAddress + 0x1E000
            self.mappedAppAddress = _mainTaskMapStartAddress + 0x20000
            self.codeCaveAddress = _mainTaskMapStartAddress + 0x3B000
            self.dataSectionStartAddress = _mainTaskMapStartAddress + 0x103000 # This offset might not work in some instances.
        elif self.targetDevice == WAGO:
            self.mappedStartAddress = _mainTaskMapStartAddress
            self.mappedAppAddress = _mainTaskMapStartAddress + 0x20010
            self.codeCaveAddress = _mainTaskMapStartAddress + 0x50000
            self.dataSectionStartAddress = _dataSectionStartAddress
            self.dataSectionEndAddress = _dataSectionEndAddress

        print('\n[*] Live instance information gathering ...')
        print('- Codesys Control PID: %s'%(self.codesysPID))
        print('- Mapped memory start address: %s'%(hex(self.mappedStartAddress)))
        print('- App file start address: %s'%(hex(self.mappedAppAddress)))
        print('- Code cave address: %s'%(hex(self.codeCaveAddress)))
        print('- Data section start address: %s'%(hex(self.dataSectionStartAddress)))
        print('- Mapped memory end address: %s'%(hex(self.mainTaskMapEndAddress)))

    def get_register_snapshot(self):
        if self.operationMode == JTAG_MODE:
            return self.lowLevelConnector.get_register_values()
        elif self.operationMode == SOFT_MODE:
            return self.lowLevelConnector.get_register_values(_pc = self.mappedAppAddress)

    def get_additional_memory_snapshot(self, _dirPath, _fileName, _startAddress, _endAddress):
        additionalFilePath = self.lowLevelConnector.get_memory_page(self.codesysPID, _startAddress, _endAddress, _dirPath, _fileName)
        self.mappedAddressesList.append([_startAddress, _endAddress, _fileName])
        return additionalFilePath

    def get_memory_snapshot(self, _dirPath):
        if self.targetDevice == BBB:
            appFilePath = self.lowLevelConnector.get_memory_page(self.codesysPID, self.mappedStartAddress, self.mainTaskMapEndAddress, _dirPath, 'MainTaskPage.bin')
            codesysFilePath_1 = self.lowLevelConnector.get_memory_page(self.codesysPID, 0x8000, 0xcfff, _dirPath, 'Codesys1.bin')
            codesysFilePath_2 = self.lowLevelConnector.get_memory_page(self.codesysPID, 0x8050000, 0x84f8fff, _dirPath, 'Codesys2.bin')
            codesysFilePath_3 = self.lowLevelConnector.get_memory_page(self.codesysPID, 0x84f9000, 0x85dafff, _dirPath, 'Codesys3.bin')
            codesysFilePath_4 = self.lowLevelConnector.get_memory_page(self.codesysPID, 0x85e2000, 0x8614fff, _dirPath, 'Codesys4.bin')
            self.mappedAddressesList = [[self.mappedStartAddress, self.mainTaskMapEndAddress, 'MainTaskPage.bin'], [0x8000, 0xcfff, 'Codesys1.bin'], [0x8050000, 0x84f8fff, 'Codesys2.bin'], [0x84f9000, 0x85dafff, 'Codesys3.bin'], [0x85e2000, 0x8614fff, 'Codesys4.bin']]
            return [appFilePath, codesysFilePath_1, codesysFilePath_2, codesysFilePath_3, codesysFilePath_4]

        elif self.targetDevice == WAGO:
            appFilePath = self.lowLevelConnector.get_memory_page(self.codesysPID, self.mappedStartAddress, self.mainTaskMapEndAddress, _dirPath, 'MainTaskPage.bin')
            appDataFilePath = self.lowLevelConnector.get_memory_page(self.codesysPID, self.dataSectionStartAddress, self.dataSectionEndAddress, _dirPath, 'MainTaskDataPage.bin')
            codesysFilePath_1 = self.lowLevelConnector.get_memory_page(self.codesysPID, 0x8000, 0xe000, _dirPath, 'Codesys1.bin')
            codesysFilePath_2 = self.lowLevelConnector.get_memory_page(self.codesysPID, 0x8050000, 0x840e000, _dirPath, 'Codesys2.bin')
            codesysFilePath_3 = self.lowLevelConnector.get_memory_page(self.codesysPID, 0x840e000, 0x84c3000, _dirPath, 'Codesys3.bin')
            codesysFilePath_4 = self.lowLevelConnector.get_memory_page(self.codesysPID, 0x84ca000, 0x84e1000, _dirPath, 'Codesys4.bin')
            self.mappedAddressesList = [[self.mappedStartAddress, self.mainTaskMapEndAddress, 'MainTaskPage.bin'], [self.dataSectionStartAddress, self.dataSectionEndAddress, 'MainTaskDataPage.bin'], [0x8000, 0xe000, 'Codesys1.bin'], [0x8050000, 0x840e000, 'Codesys2.bin'], [0x840e000, 0x84c3000, 'Codesys3.bin'], [0x84ca000, 0x84e1000, 'Codesys4.bin']]
            return [appFilePath, appDataFilePath, codesysFilePath_1, codesysFilePath_2, codesysFilePath_3, codesysFilePath_4]

    # Patch related functions
    def write_multi_locations(self, _commandCode, _address, _content, _contentSize, _endianness):
        if self.operationMode == JTAG_MODE:
            self.cpu_halt()
            self.lowLevelConnector.write_multiple_locations(_address, int(_content, 16), _contentSize, _endianness)
            self.cpu_go()
        
        elif self.operationMode == SOFT_MODE:
            if _endianness == 'little':
                _content = enhex(struct.pack('<I', int(_content, 16)))
                
            if self.patcherPreference == PYTHON:
                self.lowLevelConnector.write_in_memory(_commandCode, _address, _content)
            elif self.patcherPreference == C:
                self.lowLevelConnector.write_in_memory_c(_commandCode, _address, _content)

    # Implement JTAG based destination memory content verification
    def verify_destination_memory(self, _commandCode, _address, _content, _contentSize, _endianness):
        if self.operationMode == JTAG_MODE:
            print('[*] TODO: Implement a JTAG-based memory verification ...')
            sys.exit(0)
        elif self.operationMode == SOFT_MODE:
            if _endianness == 'little':
                _content = enhex(struct.pack('<I', int(_content, 16)))
            
            if self.patcherPreference == PYTHON:
                self.lowLevelConnector.write_in_memory(_commandCode, _address, _content)
            elif self.patcherPreference == C:
                self.lowLevelConnector.write_in_memory_c(_commandCode, _address, _content)