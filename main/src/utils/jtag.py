import os
import sys

currentDir = os.path.dirname(os.path.realpath(__file__))
parentDir = os.path.dirname(currentDir)
sys.path.append(parentDir)

from libraries.lauterbach import Lauterbach

INIT_TASK = 0xc150c340      # For BBB kernel 4.19.82-ti-rt-r31
INT_INIT_TASK = 3243295552
MAX_PROCESS_COUNT = 32768

class Jtag:
    def __init__(self):
        self.lauterbachConnector = None

    # Assume that Lauterbach is connected and initialized
    def initialize_connection(self):
        self.lauterbachConnector = Lauterbach()
        self.lauterbachConnector.Configure()
        self.lauterbachConnector.Connect()

    def check_if_halted(self):
        if self.lauterbachConnector.CPU_GetState() == 2:
            return True
        else:
            return False

    def disconnect_lauterbach(self):
        if self.check_if_halted():
            self.lauterbachConnector.CPU_Go()
        self.lauterbachConnector.Disconnect()

    def cpu_break(self):
        self.lauterbachConnector.CPU_Break()

    def cpu_go(self):
        self.lauterbachConnector.CPU_Go()

    def GetNextAddress(self, _address):
        return int(self.lauterbachConnector.HexReadMemory(_address + 0x340, 0x40, 0x4), 16) - 0x340

    def GetCommName(self, _address):
        _startAddress = _address + 0x4e0
        _tempName = ''
        
        while True:
            data = int(self.lauterbachConnector.ReadHexOneByteMemory(_startAddress, 0x40, 0x1), 16)
            if data == 0:
                break
            else:
                _tempName += chr(data)
            _startAddress += 0x1
        return _tempName

    def GetPID(self, _address):
        return self.lauterbachConnector.HexReadMemory(_address + 0x3d8, 0x40, 0x04)

    def get_codesys_address(self, _taskStructAddress):
        _nextAddress = _taskStructAddress
        _processCount = 0

        while True:
            _nextAddress = self.GetNextAddress(_nextAddress)
            _commName = self.GetCommName(_nextAddress)
            _pid = self.GetPID(_nextAddress)
            _processCount += 1

            if _nextAddress == INT_INIT_TASK or _processCount > MAX_PROCESS_COUNT or _commName == 'codesyscontrol.':
                break
        
        return _pid, _nextAddress

    def get_map_address(self, _codesysControlAddress, _selectAddress = 0x0):
        _mmAddress = int(self.lauterbachConnector.HexReadMemory(_codesysControlAddress + 0x368, 0x40, 0x4), 16)
        _mmapAddress = int(self.lauterbachConnector.HexReadMemory(_mmAddress, 0x40, 0x4), 16)
        
        _prevStartAddress = 0
        _prevEndAddress = 0
        while True:
            _vmStart = int(self.lauterbachConnector.HexReadMemory(_mmapAddress, 0x40, 0x4), 16)
            _vmEnd = int(self.lauterbachConnector.HexReadMemory(_mmapAddress + 0x4, 0x40, 0x4), 16)
            _mmapAddress = int(self.lauterbachConnector.HexReadMemory(_mmapAddress + 0x8, 0x40, 0x4), 16)

            if _selectAddress == 0:
                if _vmStart > 3063939072:
                    break
            else:
                if _selectAddress >= _vmStart and _selectAddress < _vmEnd:
                    break
            _prevStartAddress = _vmStart
            _prevEndAddress = _vmEnd

        return _prevStartAddress, _prevEndAddress

    def locate_page_inmemory(self, _taskStructAddress, _checkAddress):
        _pid, _codesysControlAddress = self.get_codesys_address(_taskStructAddress)
        _prevStartAddress, _prevEndAddress = self.get_map_address(_codesysControlAddress, _checkAddress)
        return _prevStartAddress, _prevEndAddress

    def locate_codesys_inmemory(self, _taskStructAddress):
        _pid, _codesysControlAddress = self.get_codesys_address(_taskStructAddress)
        _prevStartAddress, _prevEndAddress = self.get_map_address(_codesysControlAddress)
        return _pid, _prevStartAddress, _prevEndAddress

    def get_register_values(self):
        if not self.check_if_halted():
            self.cpu_break()
            
        _r0 = self.lauterbachConnector.ReadRegisterByName('R0')
        _r1 = self.lauterbachConnector.ReadRegisterByName('R1')
        _r2 = self.lauterbachConnector.ReadRegisterByName('R2')
        _r3 = self.lauterbachConnector.ReadRegisterByName('R3')
        _r4 = self.lauterbachConnector.ReadRegisterByName('R4')
        _r5 = self.lauterbachConnector.ReadRegisterByName('R5')
        _r6 = self.lauterbachConnector.ReadRegisterByName('R6')
        _r7 = self.lauterbachConnector.ReadRegisterByName('R7')
        _r8 = self.lauterbachConnector.ReadRegisterByName('R8')
        _r9 = self.lauterbachConnector.ReadRegisterByName('R9')
        _r10 = self.lauterbachConnector.ReadRegisterByName('R10')
        _r11 = self.lauterbachConnector.ReadRegisterByName('R11')
        _r12 = self.lauterbachConnector.ReadRegisterByName('R12')
        _r13 = self.lauterbachConnector.ReadRegisterByName('R13')
        _r14 = self.lauterbachConnector.ReadRegisterByName('R14')
        _flags = self.lauterbachConnector.ReadRegisterByName('CPSR')
        return [_r0, _r1, _r2, _r3, _r4, _r5, _r6, _r7, _r8, _r9, _r10, _r11, _r12, _r13, _r14, _flags]

    def get_memory_page(self, _pid, _startAddress, _endAddress, _dirPath, _pageName):
        if not self.check_if_halted():
            self.cpu_break()

        self.lauterbachConnector.Command('Data.SAVE.Binary ' + _dirPath + '/' + _pageName + ' ' + _pid + ':' + hex(_startAddress) + '--' + hex(_endAddress))
        return _dirPath + '/' + _pageName

    def write_multiple_locations(self, _address, _content, _contentSize, _endianness):
        self.lauterbachConnector.MultiWriteMemory(_address, 0x20, _content, _contentSize, _endianness)

    def set_breakpoint(self, _pid, _breakAddress):
        self.lauterbachConnector.Command('Break.Set ' + _pid + ':' + hex(_breakAddress) + ' /Program /Onchip')

    def read_memory(self, _address, _pid):
        self.cpu_break()
        _value = self.lauterbachConnector.Print_Command_Result('Data.long(' + _pid + ':' + hex(_address) + ')')
        self.cpu_go()
        return _value.decode("utf-8")
        
    def remove_all_breakpoint(self):
        self.lauterbachConnector.Command('Break.Delete')
