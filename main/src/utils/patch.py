import os
import sys
import archinfo

currentDir = os.path.dirname(os.path.realpath(__file__))
parentDir = os.path.dirname(currentDir)
sys.path.append(parentDir)

from pwn import *
import re
import copy
from utils.codesys import CodesysConnector
from utils.constants import *

import logging
context(arch='thumb', bits=16, endian='little')
logging.getLogger('pwnlib.asm').setLevel('ERROR')

class BasePatch(object):
    def __init__(self, _operationMode = SOFT_MODE, _patcherPreference = C, _targetDevice = BBB, _basePath = None):
        # Live instance related
        self.basePath = _basePath
        self.operationMode = _operationMode
        self.patcherPreference = _patcherPreference
        self.targetDevice = _targetDevice

        self.liveVulnInstAddress = 0
        self.liveCodeCaveAddress = 0
        self.liveMappedStartAddress = 0
        self.liveAppStartAddress = 0
        self.liveHookAddress = 0
        self.liveJumpTableBaseAddress = 0
        self.liveReturnJumpTableOffset = 0
        self.liveJumpTableEmptyAddress = 0
        self.liveVulnMemoryLocation = 0

        self.liveCodesysConnector = CodesysConnector(self.operationMode, self.targetDevice, self.patcherPreference)
        self.isLiveConnectionEstablished = False

        #Simulation related
        self.simulationHelper = None
        self.simuAppAddress = 0
        self.simuHookAddress = 0
        self.simuPatchHookBlock = 0
        self.simuJumpTableBaseAddress = 0
        self.simuJumpTableEmptyOffset = 0
        self.simuVulnMemoryLocation = 0
        self.simuVulnMemoryValue = []

        # patch related
        self.completeLocationMemoryContent = 0
        self.ifMissingTransitionFunction = False
        self.suggestedInput = 0
        self.hookLocationMemory = 0
        self.inlineHook = None
        self.hookSize = 0
        self.patch = None
        self.patchSize = 0
        self.userSpecifiedBound = 0
        self.ldrOffsetAddress = 0

    def save_pickle(self, _filePath, _object):
        if os.path.exists(_filePath):
            os.remove(_filePath)

        with open(_filePath, 'wb') as _fileObj:
            pickle.dump(_object, _fileObj)

    def load_pickle(self, _filePath):
        with open(_filePath, 'rb') as _fileObj:
            return pickle.load(_fileObj)

    def initialize(self, _simulAppAddress, _patchHookBlockState, simulationHelper, _exploitMemoryLocation, _exploitMemoryValue, _suggestedInput, _completeLocationMemoryContent, _ifMissingTransitionFunction):
        self.simuAppAddress = _simulAppAddress
        self.simuPatchHookBlockState = copy.deepcopy(_patchHookBlockState)
        self.simulationHelper = simulationHelper
        _simuljumpTableBaseAddress, _returnJumpTableIndex = self.calculate_jump_table_offset(simulationHelper)
        self.simuJumpTableBaseAddress = _simuljumpTableBaseAddress
        self.simuJumpTableEmptyOffset = self.locate_jump_table_empty_offset(simulationHelper)
        self.simuVulnMemoryLocation = _exploitMemoryLocation
        self.simuVulnMemoryValue = _exploitMemoryValue
        self.suggestedInput = _suggestedInput
        self.completeLocationMemoryContent = _completeLocationMemoryContent
        self.ifMissingTransitionFunction = _ifMissingTransitionFunction
        return _simuljumpTableBaseAddress, _returnJumpTableIndex

    def get_32_bit_address(self, _address):
        return '0x' + ('0' * (8 - len(hex(_address)[2:]))) + hex(_address)[2:]

    def create_live_user_bound_value(self, _userSpecifiedBound):
        _userSpecifiedBoundHex = hex(_userSpecifiedBound)[2:]
        _completeLocationMemoryContent = self.get_32_bit_address(self.completeLocationMemoryContent)[2:]
        _simuVulnMemoryValue = self.simuVulnMemoryValue[-1][2:]

        if _simuVulnMemoryValue == hex(self.completeLocationMemoryContent):
            return _userSpecifiedBound

        _firstHalf = _completeLocationMemoryContent.find(_simuVulnMemoryValue, 0, 4)
        _secondHalf = _completeLocationMemoryContent.find(_simuVulnMemoryValue, 4, 8)

        if _secondHalf == -1 and _firstHalf >= 0:
            _preparedContent = (('0' * (4 - len(_userSpecifiedBoundHex))) + _userSpecifiedBoundHex) + _completeLocationMemoryContent[4:]
        elif _firstHalf == -1 and _secondHalf >= 0:
            _preparedContent = _completeLocationMemoryContent[:4] + (('0' * (4 - len(_userSpecifiedBoundHex))) + _userSpecifiedBoundHex)
        else:
            return _userSpecifiedBound

        return int('0x' + _preparedContent, 16)

    def locate_jump_table_empty_offset(self, _simulationHelper):
        _currentValue = 0

        for _increment in range(0, 0x7fe, 0x4):
            _currentAddress = int(self.simuJumpTableBaseAddress, 16) + _increment
            _currentValue = int(_simulationHelper.simulationState.solver.eval(_simulationHelper.simulationState.memory.load(_currentAddress, 4, endness= archinfo.Endness.LE)))
            if _currentValue == 0:
                print('- Detected empty jump table space at {} ...\n'.format(hex(_currentAddress)))
                break
        return _increment

    def calculate_jump_table_offset(self, _simulationHelper):
        _jumpTableBaseAddress = 0
        _jumpTableIndex = 0
        _detectedOffset = False

        insns = _simulationHelper.simulationProject.factory.block(self.simuPatchHookBlockState.addr, backup_state = self.simuPatchHookBlockState).capstone.insns
        for index in range(len(insns)-1, -1, -1):
            if 'ldr' in insns[index].mnemonic:
                if not _detectedOffset and 'ldr' in insns[index-1].mnemonic:
                    _jumpTableIndex = insns[index].operands[1].mem.disp
                    print('- Simulation jump table index: {}'.format(_jumpTableIndex))
                    self.ldrOffsetAddress = insns[index].address
                    _detectedOffset = True
                elif _detectedOffset:
                    _fetchAddress = _simulationHelper.get_neighbors(_simulationHelper.loadStoreGraph.graph, hex(insns[index].address))[0]
                    _jumpTableBaseAddress = _simulationHelper.loadStoreGraph.get_node_attr(_fetchAddress)['value'][0]
                    print('- Simulation jump table base address: {}'.format(_jumpTableBaseAddress))
                    break
        return _jumpTableBaseAddress, _jumpTableIndex

    def calculate_hook_instruction(self, _simulationHelper):
        _hookAddress = 0
        _mnemonic = ''
        _operand1 = ''
        _operand2 = ''
        _immediateValue = 0
        _returnAddress = 0

        print('[*] Creating patch hook for OOB write ...')

        insns = _simulationHelper.simulationProject.factory.block(self.simuPatchHookBlockState.addr, backup_state = self.simuPatchHookBlockState).capstone.insns
        for index in range(len(insns)-1, -1, -1):
            if self.targetDevice == BBB and insns[index].mnemonic == 'blx':
                _returnAddress = insns[index].address + 2
                print('- Detected return address: {}'.format(hex(_returnAddress)))
            elif self.targetDevice == WAGO and insns[index].mnemonic == 'mov' and insns[index].reg_name(insns[index].operands[0].reg) == 'pc':
                _returnAddress = insns[index].address + 4
                print('- Detected return address: {}'.format(hex(_returnAddress)))
            elif 'ldr' in insns[index].mnemonic and insns[index].address == self.ldrOffsetAddress:
                _hookAddress = insns[index].address
                _mnemonic = insns[index].mnemonic
                _operand1 = insns[index].reg_name(insns[index].operands[0].reg)
                _operand2 = insns[index].reg_name(insns[index].operands[1].reg)
                _immediateValue = insns[index].operands[1].mem.disp

                print('- Detected hook instruction {}: {} {}, [{}, #{}] ...'.format(hex(_hookAddress), _mnemonic, _operand1, _operand2, hex(_immediateValue)))
                break

        self.simuHookAddress = _hookAddress

        # Substracting 0x1 from the address for alignment
        if self.targetDevice == BBB:
            self.liveHookAddress = (self.liveCodesysConnector.mappedAppAddress + (self.simuHookAddress - self.simuAppAddress)) - 0x1
        elif self.targetDevice == WAGO:
            self.liveHookAddress = (self.liveCodesysConnector.mappedAppAddress + (self.simuHookAddress - self.simuAppAddress))

        return '{} {}, [{}, #{}]'.format(_mnemonic, _operand1, _operand2, hex(self.simuJumpTableEmptyOffset)) 

    def create_patch_hook(self, _simulationHelper):
        # Time
        start = time.time()

        _modifiedStrHookInstruction = self.calculate_hook_instruction(_simulationHelper)
        print('- Modified hook instruction: {} ...'.format(_modifiedStrHookInstruction))

        if self.targetDevice == BBB:
            self.inlineHook = enhex(asm(_modifiedStrHookInstruction, arch = 'thumb', vma=0x8))
        elif self.targetDevice == WAGO:
            self.inlineHook = enhex(asm(_modifiedStrHookInstruction, arch = 'arm', vma=0x8))

        if '00bf' in self.inlineHook:
            self.inlineHook = self.inlineHook[:4]

        self.hookSize = int(len(self.inlineHook)/2)

        # Simulation memory value at the hook location for verification
        if self.targetDevice == BBB:
            _hookLocationMemory = self.simuPatchHookBlockState.solver.eval(self.simuPatchHookBlockState.memory.load(self.simuHookAddress - 0x1, self.hookSize))
        elif self.targetDevice == WAGO:
            _hookLocationMemory = self.simuPatchHookBlockState.solver.eval(self.simuPatchHookBlockState.memory.load(self.simuHookAddress, self.hookSize))

        self.hookLocationMemory = hex(_hookLocationMemory)[2:]
        if self.targetDevice == WAGO and len(self.hookLocationMemory) < 8:
            self.hookLocationMemory = ('0' * (8 - len(self.hookLocationMemory))) + self.hookLocationMemory

        #self.hookLocationMemory = enhex(struct.pack('<I', _hookLocationMemory))[:len(self.inlineHook)]

        print('[*] Patch hook to be written at {} ...'.format(hex(self.liveHookAddress)))
        print('- Hook in hex: %s'%(self.inlineHook))

        if self.targetDevice == BBB:
            print('- Disassembly:\n%s'%(disasm(unhex(self.inlineHook))))
        elif self.targetDevice == WAGO:
            print('- Disassembly:\n%s'%(disasm(unhex(self.inlineHook), arch = 'arm', bits = 32)))

        # Time
        print('[*] Patch hook creation time: ' + str(time.time() - start))
        
        print('--------------------')
        return self.inlineHook, self.hookSize, self.liveHookAddress

    def write_patch(self):
        if not self.isLiveConnectionEstablished:
            self.liveCodesysConnector.initialize_connector()
            self.isLiveConnectionEstablished = True

        print('[*] Overwriting jump table at {} with address value {} ...'.format(hex(self.liveJumpTableEmptyAddress), hex(self.liveCodeCaveAddress)))
        
        # Time
        start = time.time()
        # + 0x1 to remain in thumb mode
        self.liveCodesysConnector.verify_destination_memory(VERIFY_MEMORY_LOCATION, self.liveJumpTableEmptyAddress, '00' * 0x4, 0x4, 'little')
        # Time
        print('[*] Empty jump table memory verification time: ' + str(time.time() - start))

        # Time
        start = time.time()
        if self.targetDevice == BBB:
            self.liveCodesysConnector.write_multi_locations(INSTALL_JUMP_ADDRESS, self.liveJumpTableEmptyAddress, self.get_32_bit_address(self.liveCodeCaveAddress + 0x1)[2:], 0x4, 'little')
        elif self.targetDevice == WAGO:
            self.liveCodesysConnector.write_multi_locations(INSTALL_JUMP_ADDRESS, self.liveJumpTableEmptyAddress, self.get_32_bit_address(self.liveCodeCaveAddress)[2:], 0x4, 'little')
        # Time
        print('[*] Jump table memory writing time: ' + str(time.time() - start))

        # Time
        start = time.time()
        self.liveCodesysConnector.verify_destination_memory(VERIFY_MEMORY_LOCATION, self.liveCodeCaveAddress, '00' * self.patchSize, self.patchSize, 'big')
        # Time
        print('[*] Empty patch memory verification time: ' + str(time.time() - start))

        # Time
        start = time.time()
        self.liveCodesysConnector.write_multi_locations(INSTALL_MICRO_PATCH, self.liveCodeCaveAddress, self.patch, self.patchSize, 'big')
        # Time
        print('[*] Patch memory writing time: ' + str(time.time() - start))

        print('[*] Written patch at code cave address: %s ...'%(self.get_32_bit_address(self.liveCodeCaveAddress)))

    def install_patch(self):
        print('[*] Installing hook at {} ...'.format(hex(self.liveHookAddress)))

        # Time
        start = time.time()
        self.liveCodesysConnector.verify_destination_memory(VERIFY_MEMORY_LOCATION, self.liveHookAddress, self.hookLocationMemory, self.hookSize, 'big')
        # Time
        print('[*] Hook memory location verification time: ' + str(time.time() - start))

        # Time
        start = time.time()
        self.liveCodesysConnector.write_multi_locations(INSTALL_HOOK, self.liveHookAddress, self.inlineHook, self.hookSize, 'big')
        # Time
        print('[*] Hook writing time: ' + str(time.time() - start))

        print('[*] Patch installed ...')

    def release_connection(self):
        if self.operationMode == JTAG_MODE:
            self.liveCodesysConnector.release_jtag_connection()
        elif self.operationMode == SOFT_MODE:
            self.liveCodesysConnector.close_connection()


class OOBWritePatch(BasePatch):
    def __init__(self, _operationMode = SOFT_MODE, _patcherPreference = C, _targetDevice = BBB, _basePath = None, _otherPatch = False):
        BasePatch.__init__(self, _operationMode = _operationMode, _patcherPreference = _patcherPreference, _targetDevice = _targetDevice, _basePath = _basePath)

        if not _otherPatch:
            print('--------------------')
            print('[*] Created OOB Write patching object ...')

    def initialize(self, _simulAppAddress, _simulInstAddress, _patchHookBlockState, simulationHelper, _exploitMemoryLocation, _exploitMemoryValue, _suggestedInput, _completeLocationMemoryContent, _ifMissingTransitionFunction):
        _simuljumpTableBaseAddress, _returnJumpTableIndex = BasePatch.initialize(self, _simulAppAddress, _patchHookBlockState, simulationHelper, _exploitMemoryLocation, _exploitMemoryValue, _suggestedInput, _completeLocationMemoryContent, _ifMissingTransitionFunction)

        if os.path.exists('{}/VULNERABLE/PatchInformation.pkl'.format(self.basePath)):
            patchChoice = input("[*] Saved patch information detected. Use it? (Y/N): ").rstrip()
            if patchChoice == "Y" or patchChoice == "y":
                patchInfoList = self.load_pickle('{}/VULNERABLE/PatchInformation.pkl'.format(self.basePath))

                self.liveVulnInstAddress = patchInfoList[0]
                self.liveCodeCaveAddress = patchInfoList[1]
                self.liveMappedStartAddress = patchInfoList[2]
                self.liveAppStartAddress = patchInfoList[3]
                self.liveJumpTableBaseAddress = patchInfoList[4]
                self.liveReturnJumpTableOffset = patchInfoList[5]
                self.liveJumpTableEmptyAddress = patchInfoList[6]
                self.liveVulnMemoryLocation = patchInfoList[7]

                self.liveCodesysConnector.codesysPID = patchInfoList[8]
                self.liveCodesysConnector.mainTaskMapEndAddress = patchInfoList[9]
                self.liveCodesysConnector.mappedStartAddress = patchInfoList[10]
                self.liveCodesysConnector.mappedAppAddress = patchInfoList[11]
                self.liveCodesysConnector.codeCaveAddress = patchInfoList[12]
                self.liveCodesysConnector.dataSectionStartAddress = patchInfoList[13]
                self.userSpecifiedBound = patchInfoList[14]
                if self.targetDevice == WAGO:
                    self.liveCodesysConnector.dataSectionEndAddress = patchInfoList[15]
                print('[*] Patch information loaded ...')
            else:
                os.remove('{}/VULNERABLE/PatchInformation.pkl'.format(self.basePath))

        if not os.path.exists('{}/VULNERABLE/PatchInformation.pkl'.format(self.basePath)):
            _userSpecifiedBound = int(input('[*] Enter the user specified bound (Decimal)\n- Suggested bound in bytes {}: '.format(hex(self.suggestedInput))))
            self.userSpecifiedBound = self.create_live_user_bound_value(_userSpecifiedBound)

            self.liveCodesysConnector.initialize_connector()
            self.liveCodesysConnector.get_inmemory_addresses()

            self.liveVulnInstAddress = self.liveCodesysConnector.mappedAppAddress + (_simulInstAddress - self.simuAppAddress)
            self.liveCodeCaveAddress = self.liveCodesysConnector.codeCaveAddress
            self.liveMappedStartAddress = self.liveCodesysConnector.mappedStartAddress
            self.liveAppStartAddress = self.liveCodesysConnector.mappedAppAddress

            self.liveReturnJumpTableOffset = _returnJumpTableIndex
            self.liveJumpTableBaseAddress = self.liveCodesysConnector.mappedAppAddress + (int(_simuljumpTableBaseAddress, 16) - self.simuAppAddress)
            self.liveJumpTableEmptyAddress = self.liveJumpTableBaseAddress + self.simuJumpTableEmptyOffset
            self.liveVulnMemoryLocation = self.liveCodesysConnector.mappedAppAddress + (self.simuVulnMemoryLocation - self.simuAppAddress)

            livePatchInformation = [self.liveVulnInstAddress, self.liveCodeCaveAddress, self.liveMappedStartAddress, self.liveAppStartAddress, self.liveJumpTableBaseAddress, self.liveReturnJumpTableOffset, self.liveJumpTableEmptyAddress, self.liveVulnMemoryLocation]
            liveCodesysInformation = [self.liveCodesysConnector.codesysPID, self.liveCodesysConnector.mainTaskMapEndAddress, self.liveCodesysConnector.mappedStartAddress, self.liveCodesysConnector.mappedAppAddress, self.liveCodesysConnector.codeCaveAddress, self.liveCodesysConnector.dataSectionStartAddress]
            liveCodesysInformation.append(self.userSpecifiedBound)
            
            if self.targetDevice == WAGO:
                liveCodesysInformation.append(self.liveCodesysConnector.dataSectionEndAddress)

            self.save_pickle('{}/VULNERABLE/PatchInformation.pkl'.format(self.basePath), livePatchInformation + liveCodesysInformation)
            print('[*] Patch information saved ...')
            self.isLiveConnectionEstablished = True

        print('- Live user specified bound value {} ...'.format(self.get_32_bit_address(self.userSpecifiedBound)))
        print('- Live jump table base address {} ...'.format(hex(self.liveJumpTableBaseAddress)))
        print('- Live exploit memory location {} ...'.format(hex(self.liveVulnMemoryLocation)))

        print('\n[*] Initialized patching object ...')

    def create_patch(self):
        # Time
        start = time.time()

        _inlineAsm = ".align 8\n"

        if self.targetDevice == BBB:
            if self.ifMissingTransitionFunction:
                _inlineAsm += """
                    ADD R4, PC, #0x30
                    STR R14, [R4]
                    LDR R4, [PC, #0x20]
                    LDR R14, [R4]
                    LDR R4, [PC, #0x1C]
                    CMP R14, R4
                    ITT GT
                    LDRGT R14, [PC, #0x14]
                    STRGT R4, [R14]
                    LDR R14, [PC, #0x18]
                    LDR R6, [PC, #0x10]
                    """
                _inlineAsm += """
                    LDR R4, [R6, #{}]""".format(hex(self.liveReturnJumpTableOffset))
                _inlineAsm += """
                    MOVS R6, #0x0
                    BX R4"""
            else:
                _inlineAsm += """
                    ADD R4, PC, #0x28
                    STR R14, [R4]
                    LDR R4, [PC, #0x1C]
                    LDR R14, [R4]
                    LDR R4, [PC, #0x18]
                    CMP R14, R4
                    ITT GT
                    LDRGT R14, [PC, #0x10]
                    STRGT R4, [R14]
                    LDR R14, [PC, #0x10]"""
                _inlineAsm += """
                    LDR R4, [R6, #{}]""".format(hex(self.liveReturnJumpTableOffset))
                _inlineAsm += """
                    BX R4"""
            _patch = asm(_inlineAsm, arch='thumb', bits=16, endian='little')

        elif self.targetDevice == WAGO:
            _inlineAsm = ""
            if self.ifMissingTransitionFunction:
                _inlineAsm += """
                    ADD {0}, PC, #0x34
                    STR R14, [{0}]
                    LDR {0}, [PC, #0x20]
                    LDR R14, [{0}]
                    LDR {0}, [PC, #0x1C]
                    CMP R14, {0}
                    LDRGT R14, [PC, #0x10]
                    STRGT {0}, [R14]
                    LDR R14, [PC, #0x10]""".format('R6')
                _inlineAsm += """
                    LDR R6, [R14, #{}]""".format(hex(self.liveReturnJumpTableOffset))
                _inlineAsm += """
                    LDR R14, [PC, #0xC]
                    MOV PC, R6
                    """
            else:
                _inlineAsm += """
                    ADD {0}, PC, #0x34
                    STR R14, [{0}]
                    LDR {0}, [PC, #0x20]
                    LDR R14, [{0}]
                    LDR {0}, [PC, #0x1C]
                    CMP R14, {0}
                    LDRGT R14, [PC, #0x10]
                    STRGT {0}, [R14]
                    LDR R14, [PC, #0x14]
                    LDR R11, [PC, #0xC]""".format('R6')
                _inlineAsm += """
                    LDR R6, [R11, #{}]""".format(hex(self.liveReturnJumpTableOffset))
                _inlineAsm += """
                    MOV PC, R6
                    """
            _patch = asm(_inlineAsm, arch='arm', bits=32, endian='little')

        self.patch = enhex(_patch) + enhex(struct.pack('<L', int(hex(self.liveVulnMemoryLocation), base=16))) + enhex(struct.pack('<L', int(hex(self.userSpecifiedBound), base=16)))

        if (self.targetDevice == BBB and self.ifMissingTransitionFunction) or (self.targetDevice == WAGO):
            self.patch += enhex(struct.pack('<L', int(hex(self.liveJumpTableBaseAddress), base=16)))
        
        if len(self.patch) % 2 != 0:
            self.patch += '0'

        # Time
        print('[*] OOBW/OOBR patch creation time: ' + str(time.time() - start))

        self.patchSize = int(len(self.patch)/2)
        print('--------------------')
        print('[*] Patch to be written at %s ...'%(self.get_32_bit_address(self.liveCodeCaveAddress)))
        print('- Patch in hex: %s'%(self.patch))
        if self.targetDevice == BBB:
            print('- Disassembly:\n%s'%(disasm(_patch, arch='thumb', bits=16, endian='little')))
        elif self.targetDevice == WAGO:
            print('- Disassembly:\n%s'%(disasm(_patch, arch='arm', bits=32, endian='little')))

        return self.patch, self.patchSize, self.liveCodeCaveAddress
    
class OOBReadPatch(OOBWritePatch):
    def __init__(self, _operationMode = SOFT_MODE, _patcherPreference = C, _targetDevice = BBB, _basePath = None):
        OOBWritePatch.__init__(self, _operationMode = _operationMode, _patcherPreference = _patcherPreference, _targetDevice = _targetDevice, _basePath = _basePath, _otherPatch = True)

        print('--------------------')
        print('[*] Created OOB Read patching object ...')

class ImproperInputPatch(OOBWritePatch):
    def __init__(self, _operationMode = SOFT_MODE, _patcherPreference = C, _targetDevice = BBB, _basePath = None):
        OOBWritePatch.__init__(self, _operationMode = _operationMode, _patcherPreference = _patcherPreference, _targetDevice = _targetDevice, _basePath = _basePath, _otherPatch = True)

        print('--------------------')
        print('[*] Created Improper input patching object ...')

class OSCommandInjectionPatch(BasePatch):
    def __init__(self, _operationMode = SOFT_MODE, _patcherPreference = C, _targetDevice = BBB, _basePath = None):
        BasePatch.__init__(self, _operationMode = _operationMode, _patcherPreference = _patcherPreference, _targetDevice = _targetDevice, _basePath = _basePath)

        self.simuWrittenAddress = 0
        self.liveOverWrittenJumpTableAddress = 0
        self.liveOriginalFunctionAddress = 0
        self.branchRegister = ''

        print('--------------------')
        print('[*] Created OS command injection patching object ...')

    def initialize(self, _simulAppAddress, _simulInstAddress, _patchHookBlockState, simulationHelper, _exploitMemoryLocation, _exploitMemoryValue, _suggestedInput, _completeLocationMemoryContent, _ifMissingTransitionFunction, _writeAddress):
        _simuljumpTableBaseAddress, _returnJumpTableIndex = BasePatch.initialize(self, _simulAppAddress, _patchHookBlockState, simulationHelper, _exploitMemoryLocation, _exploitMemoryValue, _suggestedInput, _completeLocationMemoryContent, _ifMissingTransitionFunction)

        if os.path.exists('{}/VULNERABLE/PatchInformation.pkl'.format(self.basePath)):
            patchChoice = input("[*] Saved patch information detected. Use it? (Y/N): ").rstrip()
            if patchChoice == "Y" or patchChoice == "y":
                patchInfoList = self.load_pickle('{}/VULNERABLE/PatchInformation.pkl'.format(self.basePath))

                self.liveVulnInstAddress = patchInfoList[0]
                self.liveCodeCaveAddress = patchInfoList[1]
                self.liveMappedStartAddress = patchInfoList[2]
                self.liveAppStartAddress = patchInfoList[3]
                self.liveJumpTableBaseAddress = patchInfoList[4]
                self.liveReturnJumpTableOffset = patchInfoList[5]
                self.liveJumpTableEmptyAddress = patchInfoList[6]
                self.liveVulnMemoryLocation = patchInfoList[7]

                self.liveCodesysConnector.codesysPID = patchInfoList[8]
                self.liveCodesysConnector.mainTaskMapEndAddress = patchInfoList[9]
                self.liveCodesysConnector.mappedStartAddress = patchInfoList[10]
                self.liveCodesysConnector.mappedAppAddress = patchInfoList[11]
                self.liveCodesysConnector.codeCaveAddress = patchInfoList[12]
                self.liveCodesysConnector.dataSectionStartAddress = patchInfoList[13]

                self.liveOverWrittenJumpTableAddress = patchInfoList[14]
                self.liveOriginalFunctionAddress = patchInfoList[15]
                self.branchRegister = patchInfoList[16]

                if self.targetDevice == WAGO:
                    self.liveCodesysConnector.dataSectionEndAddress = patchInfoList[17]
                print('[*] Patch information loaded ...')
            else:
                os.remove('{}/VULNERABLE/PatchInformation.pkl'.format(self.basePath))

        if not os.path.exists('{}/VULNERABLE/PatchInformation.pkl'.format(self.basePath)):
            self.liveCodesysConnector.initialize_connector()
            self.liveCodesysConnector.get_inmemory_addresses()

            self.liveVulnInstAddress = self.liveCodesysConnector.mappedAppAddress + (_simulInstAddress - self.simuAppAddress)
            self.liveCodeCaveAddress = self.liveCodesysConnector.codeCaveAddress
            self.liveMappedStartAddress = self.liveCodesysConnector.mappedStartAddress
            self.liveAppStartAddress = self.liveCodesysConnector.mappedAppAddress

            self.liveReturnJumpTableOffset = _returnJumpTableIndex
            self.liveJumpTableBaseAddress = self.liveCodesysConnector.mappedAppAddress + (int(_simuljumpTableBaseAddress, 16) - self.simuAppAddress)
            self.liveJumpTableEmptyAddress = self.liveJumpTableBaseAddress + self.simuJumpTableEmptyOffset
            self.liveVulnMemoryLocation = self.liveCodesysConnector.mappedAppAddress + (self.simuVulnMemoryLocation - self.simuAppAddress)

            self.simuWrittenAddress = _writeAddress
            #self.liveOverWrittenJumpTableAddress = self.liveCodesysConnector.mappedAppAddress + ((int(_simuljumpTableBaseAddress, 16) + self.liveReturnJumpTableOffset) - self.simuAppAddress)
            self.liveOverWrittenJumpTableAddress = self.liveCodesysConnector.mappedAppAddress + (self.simuWrittenAddress - self.simuAppAddress)
            _simuOriginalFunctionAddress = _patchHookBlockState.solver.eval(_patchHookBlockState.memory.load(self.simuWrittenAddress, 0x4))
            self.liveOriginalFunctionAddress = self.liveCodesysConnector.mappedAppAddress + (_simuOriginalFunctionAddress - self.simuAppAddress)
            self.branchRegister = self.get_branch_utilized_Register().upper()

            livePatchInformation = [self.liveVulnInstAddress, self.liveCodeCaveAddress, self.liveMappedStartAddress, self.liveAppStartAddress, self.liveJumpTableBaseAddress, self.liveReturnJumpTableOffset, self.liveJumpTableEmptyAddress, self.liveVulnMemoryLocation]
            liveCodesysInformation = [self.liveCodesysConnector.codesysPID, self.liveCodesysConnector.mainTaskMapEndAddress, self.liveCodesysConnector.mappedStartAddress, self.liveCodesysConnector.mappedAppAddress, self.liveCodesysConnector.codeCaveAddress, self.liveCodesysConnector.dataSectionStartAddress]
            osCmdPatchSpecificInformation = [self.liveOverWrittenJumpTableAddress, self.liveOriginalFunctionAddress, self.branchRegister]

            if self.targetDevice == WAGO:
                osCmdPatchSpecificInformation.append(self.liveCodesysConnector.dataSectionEndAddress)

            self.save_pickle('{}/VULNERABLE/PatchInformation.pkl'.format(self.basePath), livePatchInformation + liveCodesysInformation + osCmdPatchSpecificInformation)
            print('[*] Patch information saved ...')
            self.isLiveConnectionEstablished = True

            print('- Live jump table base address {} ...'.format(hex(self.liveJumpTableBaseAddress)))
            print('- Live overwritten jump table address {} ...'.format(hex(self.liveOverWrittenJumpTableAddress)))
            print('- Live original function address {} ...'.format(hex(self.liveOriginalFunctionAddress)))
            print('- Live branch register: {} ...'.format(self.branchRegister))
            print('\n[*] Initialized patching object ...')

    def get_branch_utilized_Register(self):
        _block = self.simulationHelper.simulationProject.factory.block(self.simuPatchHookBlockState.addr, backup_state = self.simuPatchHookBlockState)
        _lastInstruction = _block.instruction_addrs[-1]
        
        insns = _block.capstone.insns
        for _instruction in insns:
            if self.targetDevice == BBB and _instruction.address == _lastInstruction and 'blx' in _instruction.mnemonic:
                return _instruction.reg_name(_instruction.operands[0].reg)
            elif self.targetDevice == WAGO and _instruction.address == _lastInstruction and 'mov' in _instruction.mnemonic and _instruction.reg_name(_instruction.operands[0].reg) == 'pc':
                return _instruction.reg_name(_instruction.operands[1].reg)

    def create_patch(self):
        # Time
        start = time.time()

        #_inlineAsm = ".align 8\n"
        _inlineAsm = ""
        
        if self.targetDevice == BBB:
            _inlineAsm += """
                ADD {0}, PC, #0x34
                STR R14, [{0}]
                STR R6, [{0}, #0x4]
                LDR {0}, [PC, #0x20]
                LDR R14, [{0}]
                LDR {0}, [PC, #0x20]
                CMP R14, {0}
                ITT NE
                LDRNE R14, [PC, #0x14]
                STRNE {0}, [R14]
                LDR R14, [PC, #0x18]
                LDR R6, [PC, #0x10]
                """.format(self.branchRegister)
            _inlineAsm += """
                LDR {0}, [R6, #{1}]""".format(self.branchRegister, hex(self.liveReturnJumpTableOffset))
            _inlineAsm += """
                LDR R6, [PC, #0x12]
                BX {0}""".format(self.branchRegister)
            _patch = asm(_inlineAsm, arch='thumb', bits=16, endian='little')
        
        elif self.targetDevice == WAGO:
            _inlineAsm += """
                ADD {0}, PC, #0x28
                STR R14, [{0}]
                LDR {0}, [PC, #0x18]
                LDR R14, [{0}]
                LDR {0}, [PC, #0x14]
                CMP R14, {0}
                ITT NE
                LDRNE R14, [PC, #0x8]
                STRNE {0}, [R14]
                LDR R14, [PC, #0x8]
                MOV PC, {0}
                """.format(self.branchRegister)
            _patch = asm(_inlineAsm, arch='arm', bits=32, endian='little')

        self.patch = enhex(_patch) + enhex(struct.pack('<L', int(hex(self.liveOverWrittenJumpTableAddress), base=16))) + enhex(struct.pack('>L', int(hex(self.liveOriginalFunctionAddress), base=16)))
            
        if self.targetDevice == BBB:
            self.patch += enhex(struct.pack('<L', int(hex(self.liveJumpTableBaseAddress), base=16)))

        if len(self.patch) % 2 != 0:
            self.patch += '0'

        # Time
        print('[*] OS command injection patch creation time: ' + str(time.time() - start))

        self.patchSize = int(len(self.patch)/2)
        print('--------------------')
        print('[*] Patch to be written at %s ...'%(self.get_32_bit_address(self.liveCodeCaveAddress)))
        print('- Patch in hex: %s'%(self.patch))
        if self.targetDevice == BBB:
            print('- Disassembly:\n%s'%(disasm(_patch, arch='thumb', bits=16, endian='little')))
        elif self.targetDevice == WAGO:
            print('- Disassembly:\n%s'%(disasm(_patch, arch='arm', bits=32, endian='little')))

        return self.patch, self.patchSize, self.liveCodeCaveAddress