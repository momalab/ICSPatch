import os
import sys

currentDir = os.path.dirname(os.path.realpath(__file__))
parentDir = os.path.dirname(currentDir)
sys.path.append(parentDir)

from utils.codesys import CodesysConnector
from utils.graph import Graph
from utils.constants import *
#from collections import defaultdict
import networkx as nx

import archinfo
import angr
import logging
import pickle
import copy
import struct
import re
import time
import shutil


class SimulationHelper:
    #### NESTED CLASSES ####

    class Register:
        def __init__(self):
            self.state = None

        def initialize(self, _state, _valueList):
            self.state = _state
            self.state.regs.r0 = _valueList[0]
            self.state.regs.r1 = _valueList[1]
            self.state.regs.r2 = _valueList[2]
            self.state.regs.r3 = _valueList[3]
            self.state.regs.r4 = _valueList[4]
            self.state.regs.r5 = _valueList[5]
            self.state.regs.r6 = _valueList[6]
            self.state.regs.r7 = _valueList[7]
            self.state.regs.r8 = _valueList[8]
            self.state.regs.r9 = _valueList[9]
            self.state.regs.r10 = _valueList[10]
            self.state.regs.r11 = _valueList[11]
            self.state.regs.r12 = _valueList[12]
            self.state.regs.r13 = _valueList[13]
            self.state.regs.r14 = _valueList[14]
            self.state.regs.flags = _valueList[15]
            self.state.regs.ip = 0x0
            return self.state

        def update_state(self, _state):
            self.state = _state

        def print_registers(self):
            print('----- REGISTER VIEW -----')
            print('- R0: ', hex(self.state.solver.eval(self.state.regs.r0)))
            print('- R1: ', hex(self.state.solver.eval(self.state.regs.r1)))
            print('- R2: ', hex(self.state.solver.eval(self.state.regs.r2)))
            print('- R3: ', hex(self.state.solver.eval(self.state.regs.r3)))
            print('- R4: ', hex(self.state.solver.eval(self.state.regs.r4)))
            print('- R5: ', hex(self.state.solver.eval(self.state.regs.r5)))
            print('- R6: ', hex(self.state.solver.eval(self.state.regs.r6)))
            print('- R7: ', hex(self.state.solver.eval(self.state.regs.r7)))
            print('- R8: ', hex(self.state.solver.eval(self.state.regs.r8)))
            print('- R9: ', hex(self.state.solver.eval(self.state.regs.r9)))
            print('- R10: ', hex(self.state.solver.eval(self.state.regs.r10)))
            print('- R11: ', hex(self.state.solver.eval(self.state.regs.r11)))
            print('- R12: ', hex(self.state.solver.eval(self.state.regs.r12)))
            print('- R13: ', hex(self.state.solver.eval(self.state.regs.r13)))
            print('- R14: ', hex(self.state.solver.eval(self.state.regs.r14)))
            print('- IP: ', hex(self.state.solver.eval(self.state.regs.ip)))
            print('- Flags: ', hex(self.state.solver.eval(self.state.regs.flags)))

        # Expects hex string and returns hex string
        def get_little_endian(self, _value):
            temp = _value[2:]
            temp = '0'*(8-len(temp)) + temp
            temp = temp[6:8] + temp[4:6] + temp[2:4] + temp[0:2]
            return '0x'+temp

        def print_memory(self, _start, _end):
            print('----- REGISTER MEMORY VIEW -----')
            for name in ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14']:
                _address = self.get_by_name(name)
                if _address >= _start and _address <= _end:
                    littleEndMemValue = self.get_little_endian(hex(self.state.solver.eval(self.state.memory.load(_address, 4))))
                    print('- [' + name + '] ' + hex(_address) + ': ', littleEndMemValue)

        def update_ip(self, _address):
            self.state.regs.ip = _address
            return self.state

        def get_by_name(self, _name, _state = None):
            if _state is None:
                _state = self.state

            if _name == 'r0':
                return _state.solver.eval(_state.regs.r0)
            if _name == 'r1':
                return _state.solver.eval(_state.regs.r1)
            if _name == 'r2':
                return _state.solver.eval(_state.regs.r2)
            if _name == 'r3':
                return _state.solver.eval(_state.regs.r3)
            if _name == 'r4':
                return _state.solver.eval(_state.regs.r4)
            if _name == 'r5':
                return _state.solver.eval(_state.regs.r5)
            if _name == 'r6':
                return _state.solver.eval(_state.regs.r6)
            if _name == 'r7':
                return _state.solver.eval(_state.regs.r7)
            if _name == 'r8':
                return _state.solver.eval(_state.regs.r8)
            if _name == 'r9':
                return _state.solver.eval(_state.regs.r9)
            if _name == 'r10':
                return _state.solver.eval(_state.regs.r10)
            if _name == 'r11':
                return _state.solver.eval(_state.regs.r11)
            if _name == 'r12':
                return _state.solver.eval(_state.regs.r12)
            if _name == 'r13':
                return _state.solver.eval(_state.regs.r13)
            if _name == 'r14':
                return _state.solver.eval(_state.regs.r14)
            if _name == 'ip':
                return _state.solver.eval(_state.regs.ip)
            if _name == 'flags':
                return _state.solver.eval(_state.regs.flags)

    class Memory:
        def __init__(self):
            self.state = None

        def initialize(self, _state, _memorySnapshot, _mapAddress, _memoryEndness):
            _state.memory.store(_mapAddress, _memorySnapshot, disable_actions = True, inspect = False, endness = _memoryEndness)
            self.update_state(_state)
            return _state

        # Expects hex string and returns hex string
        def get_little_endian(self, _value):
            temp = _value[2:]
            temp = '0'*(8-len(temp)) + temp
            temp = temp[6:8] + temp[4:6] + temp[2:4] + temp[0:2]
            return '0x'+temp

        def update_state(self, _state):
            self.state = _state

        def get_function_boundaries(self, _startAddress, _targetDevice):
            _traverseAddress = _startAddress + 0x8

            if _targetDevice == BBB:
                # Function Prologue: 0x4EF0010E80B56F46 Function Epilogue: 80BD (BBB)
                _functionStartInt = 5688047491169480518
                _functionEndInt = 32957
            elif _targetDevice == WAGO:
                # Function Prologue: 0x00442de90da0a0e1 Function Epilogue: 0084bde8 (WAGO)
                _functionStartInt = 16258170636414567424
                _functionEndInt = 8699368
            
            while True:
                if _targetDevice == BBB:
                    _extractedMem = self.state.solver.eval(self.state.memory.load(_traverseAddress, 0x2))
                elif _targetDevice == WAGO:
                    _extractedMem = self.state.solver.eval(self.state.memory.load(_traverseAddress, 0x4))

                if _extractedMem == _functionEndInt:
                    if _targetDevice == BBB:
                        _traverseAddress += 0x2
                    break

                _traverseAddress += 0x1
                _checkMem = self.state.solver.eval(self.state.memory.load(_traverseAddress, 0x8))
                if _checkMem == _functionStartInt:
                    return 0

            return _traverseAddress

        def print_memory(self, _startAddress, _endAddress):
            print('----- MEMORY VIEW -----')
            while _startAddress <= _endAddress:
                littleEndMemValue = self.get_little_endian(hex(self.state.solver.eval(self.state.memory.load(_startAddress, 4))))
                print('- ' + hex(_startAddress) + ': ', littleEndMemValue)
                _startAddress += 0x4
            print('--------------------\n')

    class SimulationStack:
        def __init__(self):
            self.stack = []
            self.counter = 0
            self.iecFunctionAddressList = []
            self.ifMissingTransitionFunction = False

        def push(self, _startAddress, _state, _endAddress, _ifFunctionPrologue = False, _ifVulnerable = False):
            _temp = copy.deepcopy(_state)
            self.counter += 1
            self.stack.append([self.counter, _startAddress, _temp, _endAddress, _ifFunctionPrologue, _ifVulnerable])

        def pop(self):
            _counter, _startAddress, _temp, _endAddress, _ifFunctionPrologue, _ifVulnerable = self.stack.pop()
            self.counter -= 1
            return _counter, _startAddress, _temp, _endAddress, _ifFunctionPrologue, _ifVulnerable

        def top(self):
            if self.stack:
                return self.stack[-1]

        # Get the first state in the PLC_PRG function
        def get_caller_function_state(self):
            selected_index = 0
            for index in range(self.get_length()-1, -1, -1):
                _counter, _startAddress, _task_state, _endAddress, _ifFunctionPrologue, _ifVulnerable = self.stack[index]
                if _ifFunctionPrologue:
                    selected_index = index

            return self.stack[selected_index]

        def get_previous_caller_function_state(self):
            selected_index = 0

            for index in range(self.get_length()-1, -1, -1):
                _counter, _startAddress, _task_state, _endAddress, _ifFunctionPrologue, _ifVulnerable = self.stack[index]
                if self.ifMissingTransitionFunction:
                    selected_index = index
                    break
                else:
                    if _ifFunctionPrologue:
                        selected_index = index - 1
                        break

            return self.stack[selected_index]

        def get_corresponding_state(self, _address, _simulationProject):
            for index in range(self.get_length()-1, -1, -1):
                _counter, _startAddress, _task_state, _endAddress, _ifFunctionPrologue, _ifVulnerable = self.stack[index]
                _taskBlock = _simulationProject.factory.block(_task_state.addr, backup_state = _task_state)
                _startInstructionAddress = _taskBlock.instruction_addrs[0]
                _endInstructionAddress = _taskBlock.instruction_addrs[-1]

                if _startInstructionAddress <= _address <= _endInstructionAddress:
                    return _task_state

        def get_length(self):
            return len(self.stack)

        def mark_top_vulnerable(self):
            self.stack[-1][-1] = True

    class VulnerabilityInformation:
        def __init__(self, _appStartAddress, _writeAddress, _expression, _type, _patchBlockState, _vulnBlockState = None):
            self.appStartAddress = _appStartAddress
            self.writeAddress = _writeAddress
            self.expression = _expression
            self.vulnerabilityType = _type

            # Vulnerable block related information
            self.patchBlockState = copy.deepcopy(_patchBlockState)
            self.vulnBlockStartAddress = 0
            if _vulnBlockState:
                self.vulnBlockState = copy.deepcopy(_vulnBlockState)
            else:
                self.vulnBlockState = _vulnBlockState
            self.vulnBlockEndAddress = 0
            self.preparedInsBlock = None

            # Exploit information
            self.exploitInstructionLocation = 0
            self.exploitMemoryLocation = 0
            self.completeLocationMemoryContent = 0
            self.exploitMemoryValue = ''
            self.ifMissingTransitionFunction = False

            # Input suggestion information
            self.suggestedUserInput = 0

        def initialize_exploit_information(self, _exploitInstructionLocation, _exploitMemoryLocation, _exploitMemoryValue, _suggestedSize, _completeLocationMemoryContent, _ifMissingTransitionFunction):
            self.exploitInstructionLocation = _exploitInstructionLocation
            self.exploitMemoryLocation = _exploitMemoryLocation
            self.exploitMemoryValue = _exploitMemoryValue
            self.suggestedUserInput = _suggestedSize
            self.completeLocationMemoryContent = _completeLocationMemoryContent
            self.ifMissingTransitionFunction = _ifMissingTransitionFunction

    class PatchVerifier:
        def __init__(self):
            self.inlineHook = None
            self.hookSize = None
            self.liveHookAddress = None
            self.patch = None
            self.patchSize = None
            self.liveCodeCaveAddress = None

        def initialize(self, _inlineHook, _hookSize, _liveHookAddress, _patch, _patchSize, _liveCodeCaveAddress):
            self.inlineHook = _inlineHook
            self.hookSize = _hookSize
            self.liveHookAddress = _liveHookAddress
            self.patch = _patch
            self.patchSize = _patchSize
            self.liveCodeCaveAddress = _liveCodeCaveAddress

    class CustomRule:
        def __init__(self):
            self.rule_text = ""

            self.rule_name = ""
            self.rule_action = None

            self.rule_type = None
            self.original_eval_condition = ""
            self.eval_condition = ""
            self.message = ""

        def parse(self, rule_text):
            self.rule_text = rule_text

            try:
                rule_list = self.rule_text.split(":")
                rule_parameters = rule_list[0].strip()
                rule_definition = rule_list[1].strip()

                # RULE_NAME
                rule_list = rule_parameters.split()
                self.rule_name = rule_list[0].strip()

                # RULE_ACTION
                rule_action = rule_list[1].strip()[1:-1]
                if rule_action == "WARN":
                    self.rule_action = RULE_WARN
                elif rule_action == "ALERT":
                    self.rule_action = RULE_ALERT
                else:
                    raise("[X] RULE_ACTION not defined properly. ICSPatch supports [ALERT and WARN].")

                match = re.search("(.+?) \[(.+?)\] \"(.+?)\"", rule_definition)

                # RULE_TYPE
                rule_type = match.group(1)
                if rule_type == "OOB_WRITE":
                    self.rule_type = OOB_WRITE
                elif rule_type == "OOB_READ":
                    self.rule_type = OOB_READ
                elif rule_type == "IMPROPER_INPUT_VALIDATION":
                    self.rule_type = OOB_WRITE
                elif rule_type == "OS_COMMAND_INJECTION":
                    self.rule_type = OS_COMMAND_INJECTION
                else:
                    raise("[X] RULE_TYPE not defined properly. ICSPatch supports [OOB_WRITE, OOB_READ, IMPROPER_INPUT_VALIDATION, and OS_COMMAND_INJECTION].")

                # EVAL_CONDITION
                self.eval_condition = match.group(2)
                self.original_eval_condition = self.eval_condition

                # MESSAGE
                self.message = match.group(3)

            except:
                print("[X] Failure while parsing ICSPatch rule.")
                print("[*] Rule format: RULE_NAME (RULE_ACTION): RULE_TYPE [CHECK_ADDRESS CONDITION SPECIAL_ADDRESS] 'MESSAGE'")
                print("Example: OUT_OF_BOUNDS_WRITE (ALERT): OOB_WRITE [WRITE_ADDRESS > CODESYS_TEXT] \"Out-of-bounds vulnerability detected.\"")
                exit(0)

    ####

    def __init__(self, _experimentType = VULNERABLE_EXPERIMENT, _operationMode = JTAG_MODE, _targetDevice = BBB, _cleanStateTracker = {}, _systemLibrary = False):
        print('--------------------')
        self.codesysConnector = CodesysConnector(_operationMode, _targetDevice)
        if _experimentType == CLEAN_EXPERIMENT:
            print('[*] Setting up Clean Experiment ...')
        elif _experimentType == VULNERABLE_EXPERIMENT:
            print('[*] Setting up Vulnerable Experiment ...')
        elif _experimentType == DEBUG_EXPERIMENT:
            print('[*] Setting up Debug Experiment ...')
        
        self.operationMode = _operationMode
        self.targetDevice = _targetDevice
        print('[*] Created CodesysConnector object ...')

        # Initialize shared simulation related state variables
        self.initialize_per_simulation_states(_cleanStateTracker)
        if _systemLibrary:
            self.stackObj.ifMissingTransitionFunction = True
            print('[*] System Library explicitly identified by the user ...')
        
        # Simulation related
        self.simulationProject = None
        self.simulationState = None
        self.simulationManager = None
        self.experimentType = _experimentType
        self.experimentDirName = None

        # Simulation addresses
        self.simulationStartAddresses = 0
        self.simulationEndAddresses = 0

        # memory snapshot
        self.appMemSnapshot = None
        self.appDataMemSnapshot = None
        self.codesysMemSnapshot_1 = None
        self.codesysMemSnapshot_2 = None
        self.codesysMemSnapshot_3 = None
        self.codesysMemSnapshot_4 = None

        # additional requested memory snapshots
        self.requestedAdditionalMemorySnapshots = []
        self.codesysAdditionalMemorySnapshots = []

        # Patch Verifier
        self.patchVerifier = self.PatchVerifier()
        print('[*] Created Patch Verifier object ...')

    def initialize_per_simulation_states(self, _cleanStateTracker = {}):
        # Tracking simulation specifics
        self.registerObj = self.Register()
        print('[*] Created Register object ...')
        self.memoryObj = self.Memory()
        print('[*] Created Memory object ...')
        self.stackObj = self.SimulationStack()
        print('[*] Created Simulation Stack object ...')
        self.customRuleObj = self.CustomRule()
        print('[*] Created Custom Rule object ...')

        # tracking simulation states
        self.simulationInitialEntry = False
        self.simulationInitialExit = False
        self.simulationReturnEntry = False
        self.simulationEnd = False
        self.simulationStackEnabled = False

        # load store graph
        self.detectedPlcPrg = False ###
        self.detectedNextFunction = False ###
        self.forceEnableGraphCreation = False ###
        self.faultAddressList = []
        self.faultAddress = None
        self.loadStoreGraph = Graph()

        # Per function store graph
        self.perFunctionStoreGraph = None
        self.runtimeBoundaryAddress = 0

        # tracking vulnerable states
        self.vulnerabilityList = []
        self.vulnerabilityInsAddress = 0
        self.vulnerabilityType = None
        self.vulnerabilityDetected = False
        self.vulnerabilitySuggestedSize = 0
        self.vulnerabilityOperatedAddress = 0
        self.vulnerabilityOperatedExpression = 0
        self.vulnerabilityState = None

        # Clean state tracking
        self.functionCounter = 0
        self.currentFunctionCounter = 0
        self.currentFunctionStack = [0]
        self.currentCodesysStackReg = 0

        self.nextBlockReCalculate = False
        self.cleanWriteTracker = _cleanStateTracker
        self.cleanReadTracker = _cleanStateTracker
        self.disableWriteTracker = False
        self.disableReadTracker = False

        # Detecting jump table address in simulation
        self.detectedJumpTableBranch = False
        self.calculatedJumpTableBaseAddress = False
        self.jumpTableBaseAddress = 0

        # Patch state tracking
        self.patchVerificationFailed = False
        self.liveCodeCaveAddress = 0
        self.patchSize = 0
        self.patchDangerousInstruction = []
        
    def setup_project(self, chosen_vuln = None, experiment_dir = None):
        print('--------------------')
        print('[*] Reduce angr logging level to \'ERROR\' ...')
        logging.getLogger('angr').setLevel('ERROR')

        _arch = archinfo.ArchARM(archinfo.Endness.LE)
        self.simulationProject = angr.project.load_shellcode("\x90".encode(), _arch, start_offset = 0, load_address = 0, thumb = True, support_selfmodifying_code = True)
        print('[*] Created a blank angr project with thumb LE ...')
        self.simulationState = self.simulationProject.factory.blank_state()
        print('[*] Created a blank simulation state...')

        infrastructure = ["aircraft_control", "anaerobic_reactor", "chemical_plant", "desalination_plant", "smart_grid"]
        selected_sample = experiment_dir

        if not experiment_dir:
            print("\nSelect Experiment:\n-------------------------")
            print("0. Evaluate\n1. Live")
            chosen_experiment = int(input("Choice: "))

            if chosen_experiment == 1:
                live_dir = "bin/internal/live_example"
                for filename in os.listdir(live_dir):
                    file_path = os.path.join(live_dir, filename)
                    try:
                        if os.path.isfile(file_path) or os.path.islink(file_path):
                            os.unlink(file_path)
                        elif os.path.isdir(file_path):
                            shutil.rmtree(file_path)
                    except Exception as e:
                        print('Failed to delete %s. Reason: %s' % (file_path, e))
                        
                # Create appropriate folders
                if not os.path.exists("{}/{}".format(live_dir, "CLEAN")):
                    os.mkdir("{}/{}".format(live_dir, "CLEAN"))
                if not os.path.exists("{}/{}".format(live_dir, "VULNERABLE")):
                    os.mkdir("{}/{}".format(live_dir, "VULNERABLE"))
                if not os.path.exists("{}/{}".format(live_dir, "DEBUG")):
                    os.mkdir("{}/{}".format(live_dir, "DEBUG"))
                selected_sample = live_dir
    
            else:
                print("\nSelect Infrastructure:\n-------------------------")
                for counter, infra in enumerate(infrastructure):
                    print("{}. {}".format(counter, infra))
                chosen_infra = int(input("Choice: "))

                scan_path = "bin/internal/{}/{}".format(infrastructure[chosen_infra], chosen_vuln)
                sub_directories = [ f.path for f in os.scandir(scan_path) if f.is_dir() ]

                print("\nSelect Test Sample:\n-------------------------")
                for counter, sub_directory in enumerate(sub_directories):
                    print("{}. {}".format(counter, sub_directory))
                chosen_sub_directory = int(input("Choice: "))
                selected_sample = sub_directories[chosen_sub_directory]

        if self.experimentType == CLEAN_EXPERIMENT:
                self.experimentDirName = "{}/{}".format(selected_sample, "CLEAN")
        elif self.experimentType == VULNERABLE_EXPERIMENT:
            self.experimentDirName = "{}/{}".format(selected_sample, "VULNERABLE")
        elif self.experimentType == DEBUG_EXPERIMENT:
            self.experimentDirName = "{}/{}".format(selected_sample, "DEBUG")

        return selected_sample

    def save_pickle(self, _filePath, _object):
        if os.path.exists(_filePath):
            os.remove(_filePath)

        with open(_filePath, 'wb') as _fileObj:
            pickle.dump(_object, _fileObj)

    def load_pickle(self, _filePath):
        with open(_filePath, 'rb') as _fileObj:
            return pickle.load(_fileObj)

    def get_additional_plc_snapshots(self):
        for _startAddress, _endAddress, _fileName in self.requestedAdditionalMemorySnapshots:
            print('\n[*] Extracting additional memory snapshot from {}-{}...'.format(hex(_startAddress), hex(_endAddress)))
            _filePath = self.codesysConnector.get_additional_memory_snapshot('{}'.format(self.experimentDirName), _fileName, _startAddress, _endAddress)
            _memorySnapshot = open(_filePath, "rb").read()
            self.codesysAdditionalMemorySnapshots.append([_startAddress, _memorySnapshot])

    def load_local_additional_snapshots(self):
        for _startAddress, _endAddress, _fileName in self.codesysConnector.mappedAddressesList:
            if not _fileName in ['MainTaskPage.bin', 'Codesys1.bin', 'Codesys2.bin', 'Codesys3.bin', 'Codesys4.bin']:
                _filePath = '{}/'.format(self.experimentDirName) + _fileName
                _memorySnapshot = open(_filePath, "rb").read()
                self.codesysAdditionalMemorySnapshots.append([_startAddress, _memorySnapshot])

    def get_plc_snapshot_update(self, _requestedAdditionalMemorySnapshots = []):
        self.requestedAdditionalMemorySnapshots = _requestedAdditionalMemorySnapshots

        if len(os.listdir(self.experimentDirName)) != 0:
            print('\n[*] Past PLC snapshot detected ...')
            simulationInfoList = self.load_pickle('{}/SimulationInformation.pkl'.format(self.experimentDirName))
            self.codesysConnector.codesysPID = simulationInfoList[0]
            self.codesysConnector.mainTaskMapEndAddress = simulationInfoList[1]
            self.codesysConnector.mappedStartAddress = simulationInfoList[2]
            self.codesysConnector.mappedAppAddress = simulationInfoList[3]
            self.codesysConnector.codeCaveAddress = simulationInfoList[4]
            self.codesysConnector.dataSectionStartAddress = simulationInfoList[5]
            
            if self.targetDevice == WAGO:
                self.codesysConnector.dataSectionEndAddress = simulationInfoList[6]

            self.simulationStartAddresses = self.codesysConnector.mappedAppAddress
            print('- Stored Map Address: {} ...'.format(hex(self.codesysConnector.mappedStartAddress)))
            print('- Stored App Start Address: {} ...'.format(hex(self.codesysConnector.mappedAppAddress)))
            print('- Stored Data Start Address: {} ...'.format(hex(self.codesysConnector.dataSectionStartAddress)))
            print('[*] Loaded important addresses ...')

            self.registerVector = self.load_pickle('{}/RegisterSnapshot.pkl'.format(self.experimentDirName))
            print('[*] Loaded register values ...')
            self.appMemSnapshot = open('{}/MainTaskPage.bin'.format(self.experimentDirName), "rb").read()
            if self.targetDevice == WAGO:
                self.appDataMemSnapshot = open('{}/MainTaskDataPage.bin'.format(self.experimentDirName), "rb").read()
            self.codesysMemSnapshot_1 = open('{}/Codesys1.bin'.format(self.experimentDirName), "rb").read()
            self.codesysMemSnapshot_2 = open('{}/Codesys2.bin'.format(self.experimentDirName), "rb").read()
            self.codesysMemSnapshot_3 = open('{}/Codesys3.bin'.format(self.experimentDirName), "rb").read()
            self.codesysMemSnapshot_4 = open('{}/Codesys4.bin'.format(self.experimentDirName), "rb").read()
            print('[*] Loaded memory snapshots ...')

            self.codesysConnector.mappedAddressesList = self.load_pickle('{}/MappedAddressList.pkl'.format(self.experimentDirName))
            self.load_local_additional_snapshots()
            print('[*] Loaded additional memory snapshots ...')
            
        else:
            print('--------------------')
            self.codesysConnector.initialize_connector()
            print('\n[*] Initialized CodesysConnector object ...')

            # Get important codesys specific addresses
            self.codesysConnector.get_inmemory_addresses()

            if self.targetDevice == BBB:
                simulationInfoList = [self.codesysConnector.codesysPID, self.codesysConnector.mainTaskMapEndAddress, self.codesysConnector.mappedStartAddress, self.codesysConnector.mappedAppAddress, self.codesysConnector.codeCaveAddress, self.codesysConnector.dataSectionStartAddress]
            elif self.targetDevice == WAGO:
                simulationInfoList = [self.codesysConnector.codesysPID, self.codesysConnector.mainTaskMapEndAddress, self.codesysConnector.mappedStartAddress, self.codesysConnector.mappedAppAddress, self.codesysConnector.codeCaveAddress, self.codesysConnector.dataSectionStartAddress, self.codesysConnector.dataSectionEndAddress]

            self.save_pickle('{}/SimulationInformation.pkl'.format(self.experimentDirName), simulationInfoList)
            print('[*] Gathered important addresses ...')

            # Setup registers and update simulation state
            if self.operationMode == JTAG_MODE:
                self.codesysConnector.set_break_at_app_start()
                print('[*] Setup hardware breakpoint at %s ...'%(hex(self.codesysConnector.mappedAppAddress)))

                while True:
                    if self.codesysConnector.check_if_cpu_halted():
                        print('[*] Execution halted, gathering snapshots ...')
                        break

            # Time
            start = time.time()

            # Setup memory state
            self.simulationStartAddresses = self.codesysConnector.mappedAppAddress
            if self.targetDevice == BBB:
                appFilePath, codesysFilePath_1, codesysFilePath_2, codesysFilePath_3, codesysFilePath_4 = self.codesysConnector.get_memory_snapshot('{}'.format(self.experimentDirName))
            elif self.targetDevice == WAGO:
                appFilePath, appDataFilePath, codesysFilePath_1, codesysFilePath_2, codesysFilePath_3, codesysFilePath_4 = self.codesysConnector.get_memory_snapshot('{}'.format(self.experimentDirName))
            self.get_additional_plc_snapshots()

            self.appMemSnapshot = open(appFilePath, "rb").read()
            if self.targetDevice == WAGO:
                self.appDataMemSnapshot = open(appDataFilePath, "rb").read()
            self.codesysMemSnapshot_1 = open(codesysFilePath_1, "rb").read()
            self.codesysMemSnapshot_2 = open(codesysFilePath_2, "rb").read()
            self.codesysMemSnapshot_3 = open(codesysFilePath_3, "rb").read()
            self.codesysMemSnapshot_4 = open(codesysFilePath_4, "rb").read()

            # Time
            print('[*] Time for extracting and loading memory hexdumps: ' + str(time.time() - start))

            self.save_pickle('{}/MappedAddressList.pkl'.format(self.experimentDirName), self.codesysConnector.mappedAddressesList)
            print('[*] Extracted memory snapshots ...')

            self.registerVector = self.codesysConnector.get_register_snapshot()
            self.save_pickle('{}/RegisterSnapshot.pkl'.format(self.experimentDirName), self.registerVector)
            print('[*] Collected register snapshot ...')

            if self.operationMode == JTAG_MODE:
                self.codesysConnector.remove_app_breakpoint()
                print('[*] Removed hardware breakpoint ...')
                self.codesysConnector.cpu_go()
                print('[*] PLC execution resumed ...')

                self.codesysConnector.release_jtag_connection()
                print('[*] Released JTAG communication ...')
            elif self.operationMode == SOFT_MODE:
                self.codesysConnector.close_connection()
                print('[*] Closed socket communication ...')

    def initialize_simulation_state(self):
        # Time
        start = time.time()

        print('--------------------')
        self.simulationState = self.registerObj.initialize(self.simulationState, self.registerVector)
        print('[*] Initialized Register object with snapshot data ...')

        self.simulationState = self.memoryObj.initialize(self.simulationState, self.appMemSnapshot, self.codesysConnector.mappedStartAddress, archinfo.Endness.BE)
        print('[*] Initialized Memory object with MainTask snapshot data ...')
        if self.targetDevice == WAGO:
            self.simulationState = self.memoryObj.initialize(self.simulationState, self.appDataMemSnapshot, self.codesysConnector.dataSectionStartAddress, archinfo.Endness.BE)
            print('[*] Initialized Memory object with MainTask data section snapshot ...')

        if self.targetDevice == BBB or self.targetDevice == WAGO:
            self.simulationState = self.memoryObj.initialize(self.simulationState, self.codesysMemSnapshot_1, 0x8000, archinfo.Endness.BE)
        print('[*] Initialized Memory object with Codesys snapshot data (1) ...')

        if self.targetDevice == BBB or self.targetDevice == WAGO:
            self.simulationState = self.memoryObj.initialize(self.simulationState, self.codesysMemSnapshot_2, 0x8050000, archinfo.Endness.BE)
        print('[*] Initialized Memory object with Codesys snapshot data (2) ...')

        if self.targetDevice == BBB:
            self.simulationState = self.memoryObj.initialize(self.simulationState, self.codesysMemSnapshot_3, 0x84f9000, archinfo.Endness.BE)
        elif self.targetDevice == WAGO:
            self.simulationState = self.memoryObj.initialize(self.simulationState, self.codesysMemSnapshot_3, 0x840e000, archinfo.Endness.BE)
        print('[*] Initialized Memory object with Codesys snapshot data (3) ...')

        if self.targetDevice == BBB:
            self.simulationState = self.memoryObj.initialize(self.simulationState, self.codesysMemSnapshot_4, 0x85e2000, archinfo.Endness.BE)
        elif self.targetDevice == WAGO:
            self.simulationState = self.memoryObj.initialize(self.simulationState, self.codesysMemSnapshot_4, 0x84ca000, archinfo.Endness.BE)
        print('[*] Initialized Memory object with Codesys snapshot data (4) ...')

        for _starAddress, _memorySnapshot in self.codesysAdditionalMemorySnapshots:
            self.simulationState = self.memoryObj.initialize(self.simulationState, _memorySnapshot, _starAddress, archinfo.Endness.BE)
            print('[*] Initialized Memory object with additional Codesys snapshot data at {} (additional) ...'.format(hex(_starAddress)))

        if self.operationMode == SOFT_MODE and self.targetDevice == BBB:
            self.simulationState.mem[self.simulationStartAddresses - 0x12b8].uint32_t = self.simulationStartAddresses + 0x103ab8
        '''if self.operationMode == SOFT_MODE and self.targetDevice == WAGO:
            self.simulationState.mem[self.simulationStartAddresses - 0x122e].uint8_t = 0
            self.simulationState.mem[self.simulationStartAddresses - 0x12a4].uint32_t = ((self.simulationStartAddresses - 0x12a0) - 0x28)
            self.simulationState.mem[self.simulationStartAddresses - 0x12a0].uint32_t = 0'''
        print('[*] Fixed a stack location for starting simulation ...')

        if self.targetDevice == BBB:
            self.simulationState = self.registerObj.update_ip(self.simulationStartAddresses + 0x1)
        elif self.targetDevice == WAGO:
            self.simulationState = self.registerObj.update_ip(self.simulationStartAddresses)
        print('[*] Modified IP to %s ...'%(hex(self.simulationStartAddresses)))

        # Time
        print('[*] Time for loading hexdumps in angr: ' + str(time.time() - start))

    def verify_patch(self, _inlineHook, _hookSize, _liveHookAddress, _patch, _patchSize, _liveCodeCaveAddress, _liveJumpTableEmptyAddress, _liveJumpTableBaseAddress, _patchVulnerabilityType):
        print('--------------------')
        print('[*] Initiating patch verification ...')

        # Time
        start = time.time()

        self.patchVerifier.initialize(_inlineHook, _hookSize, _liveHookAddress, _patch, _patchSize, _liveCodeCaveAddress)
        self.setup_simulation(self.simulationState)

        # Fix simulation tracking state variables
        self.simulationInitialEntry = False
        self.simulationInitialExit = False
        self.simulationReturnEntry = False
        self.simulationEnd = False
        self.vulnerabilityDetected = False

        self.initialize_per_simulation_states()
        self.liveCodeCaveAddress = _liveCodeCaveAddress
        self.patchSize = _patchSize
        self.liveJumpTableBaseAddress = _liveJumpTableBaseAddress
        self.liveJumpTableEmptyAddress = _liveJumpTableEmptyAddress
        self.patchVulnerabilityType = _patchVulnerabilityType
        self.patchLoopCount = 0

        # Write patch, inline hook and the address table modification to the simulation state
        print("[*] Written patch, code cave address, and inline hook in simulation state ...")
        self.simulationState = self.memoryObj.initialize(self.simulationState, _liveCodeCaveAddress, _liveJumpTableEmptyAddress, archinfo.Endness.LE)
        self.simulationState = self.memoryObj.initialize(self.simulationState, bytes.fromhex(_patch), _liveCodeCaveAddress, archinfo.Endness.BE)
        self.simulationState = self.memoryObj.initialize(self.simulationState, int(_inlineHook, 16).to_bytes(4, byteorder='big'), _liveHookAddress, archinfo.Endness.BE)

        self.patchDangerousInstruction = ["swi", "svc", "push", "pop", "stm", "ldm", "cdp", "ldc", "stc", "mcr", "mrc"]
        self.enable_patch_write_verification()
        self.enable_patch_mnemonic_verification()
        self.perform_simulation(simulType = NON_INTERACTIVE, isPatchVerification = True)

        # Time
        print('[*] Time for patch verification in angr: ' + str(time.time() - start))
        return False if self.patchVerificationFailed else True

    def check_mnemonic(self, current_mnemonic):
        for dangerous_mnemonic in self.patchDangerousInstruction:
            if dangerous_mnemonic in current_mnemonic:
                return True
        return False

    def enable_patch_write_verification(self):
        print('[*] Enabling patch verification write tracking ...')
        self.simulationState.inspect.b('mem_write', when = angr.BP_BEFORE, action = self.patch_write_verification)

    def patch_write_verification(self, _state):
        _instructionAddress = _state.scratch.ins_addr
        _writeAddress = _state.solver.eval(_state.inspect.mem_write_address)

        # Detect if the write operation is in the newly added patch
        _patchEnd = self.liveCodeCaveAddress + self.patchSize
        if self.liveCodeCaveAddress <= _instructionAddress <= _patchEnd:
            if self.patchVulnerabilityType == OS_COMMAND_INJECTION and _writeAddress >= self.liveJumpTableBaseAddress and _state.solver.eval(_state.mem[self.liveJumpTableEmptyAddress].uint32_t.resolved) != self.liveCodeCaveAddress:
                print('\n[*] Detected unknown address at empty address table location ...\n')
                self.patchVerificationFailed = True
            if self.patchVulnerabilityType != OS_COMMAND_INJECTION and (_writeAddress >= self.liveJumpTableBaseAddress or self.simulationStartAddresses <= _writeAddress <= self.liveCodeCaveAddress):
                print('\n[*] Detected memory write at invalid location ...\n')
                self.patchVerificationFailed = True

    def enable_patch_mnemonic_verification(self):
        print('[*] Enabling dangerous instruction detection ...')
        self.simulationState.inspect.b('irsb', when = angr.BP_BEFORE, action = self.patch_mnemonic_verification)

    def patch_mnemonic_verification(self, _state):
        _patchEnd = self.liveCodeCaveAddress + self.patchSize

        # Backward loop check
        _block = self.simulationProject.factory.block(_state.addr, backup_state = _state)
        _blockEndAddress = _block.instruction_addrs[-1]

        if self.liveCodeCaveAddress <= _blockEndAddress <= _patchEnd:
            self.patchLoopCount += 1
            if self.patchLoopCount > 1:
                print('\n[*] Detected loop in the patch ...\n')
                self.patchVerificationFailed = True
                return
        else:
            self.patchLoopCount = 0

        # Checking dangerous instructions
        insns = _block.capstone.insns
        for _instruction in insns:
            if self.liveCodeCaveAddress <= _instruction.address <= _patchEnd and self.check_mnemonic(_instruction.mnemonic):
                print('[*] Detected dangerous instruction in the patch ...')
                self.patchVerificationFailed = True
                break

    def setup_simulation(self, _simulState = None):
        initialState = False
        if not _simulState:
            _simulState = self.simulationState
            initialState = True

        print('--------------------')
        self.simulationManager = self.simulationProject.factory.simulation_manager(_simulState)
        print('[*] Setup simulation manager ...')
        self.simulationManager.use_technique(angr.exploration_techniques.DFS())
        print('[*] Choosing DFS exploration technique ...')

        if initialState:
            self.simulationEndAddresses = self.memoryObj.get_function_boundaries(self.simulationStartAddresses, self.targetDevice)
            print('[*] Calculated the simulation end address as %s ...'%(hex(self.simulationEndAddresses)))

    # Memory load to print memory content disabled to avoid issues with interactive oob_read
    def print_all(self, _active):
        self.print_block(_active)
        self.registerObj.print_registers()
        #self.registerObj.print_memory(self.codesysConnector.mappedStartAddress, self.codesysConnector.mainTaskMapEndAddress)
        #self.memoryObj.print_memory(self.registerObj.get_by_name('r13')-0x10, self.registerObj.get_by_name('r7')+0x10)

    def print_block(self, _active):
        print('----- BLOCK DISASSEMBLY -----')
        _block = self.simulationProject.factory.block(_active.addr, backup_state = _active)
        instruction_addrs = _block.instruction_addrs
        print("Instruction # in block: {}".format(len(instruction_addrs)))
        _block.pp()

    def check_last_address_in_block(self, _state):
        _block = self.simulationProject.factory.block(_state.addr, backup_state = _state)

        if not _block.instruction_addrs:
            return False

        _last_instruction_address = _block.instruction_addrs[-1]
        if _last_instruction_address == self.simulationEndAddresses:
            return True
        return False

    def perform_simulation(self, simulType = NON_INTERACTIVE, isPatchVerification = False):
        # Time
        start = time.time()

        print('--------------------')
        print('[*] Beginning simulation ...')
        while self.simulationManager.active:
            print(self.simulationManager, self.simulationManager.active)

            for _active in self.simulationManager.active:
                self.simulationManager.step()
                print('- Active Address: ', hex(_active.addr))
                if self.simulationStartAddresses <= _active.addr < self.simulationEndAddresses and not self.simulationInitialEntry:
                    self.simulationInitialEntry = True
                elif _active.addr > self.simulationEndAddresses and self.simulationInitialEntry:
                    self.simulationInitialExit = True

                if self.simulationStartAddresses <= _active.addr < self.simulationEndAddresses and self.simulationInitialExit:
                    self.simulationReturnEntry = True
                # Check if this does not create an issue for BBB. Might need to revert back to the original code.
                #elif _active.addr >= self.simulationEndAddresses and self.simulationReturnEntry:
                if self.check_last_address_in_block(_active) and self.simulationReturnEntry:
                    self.simulationEnd = True

                self.registerObj.update_state(_active)
                self.memoryObj.update_state(_active)

                if simulType == INTERACTIVE:
                    self.print_all(_active)

            # Vulnerability information
            if self.vulnerabilityDetected:
                # Time
                print('[*] Angr execution time of the control application: ' + str(time.time() - start))

                self.save_pickle('{}/LoadStoreGraph.pkl'.format(self.experimentDirName), self.loadStoreGraph.graph)
                self.get_vulnerability_information(_active)
            
            if self.simulationEnd:
                break

            if simulType == INTERACTIVE:
                input()

        if self.vulnerabilityDetected and isPatchVerification:
            self.patchVerificationFailed = True

    def store_simulation_memory(self, _storeMessage, _storeData, _storeAddress):
        self.simulationState = self.memoryObj.initialize(self.simulationState, _storeData, _storeAddress, archinfo.Endness.BE)
        print('[*] Initialized Memory object with {} ...'.format(_storeMessage))

    def exit_simulation(self):
        self.codesysConnector.release_jtag_connection()
    
    #### Instrumentation Code

    # Handling stack frame offset for legitimate read and write
    def enable_function_start_tracking(self):
        print('[*] Enabling function start tracking ...')
        self.simulationState.inspect.b('irsb', when = angr.BP_BEFORE, action = self.check_function_start_state)

    def check_function_start_state(self, _state):
        _blockStartAddress = 0
        _block = self.simulationProject.factory.block(_state.addr, backup_state = _state)

        if self.targetDevice == BBB:
            # PC is +1 because of thumb mode, so -1 to get the actual memory content
            _blockStartAddress = _state.solver.eval(_state.regs.ip) - 0x1
            _blockEndAddress = _block.instruction_addrs[-1] - 1
            _lastInstruction = int('0x' + self.get_32_bit_address(_state.solver.eval(_state.mem[_blockEndAddress].uint32_t.resolved))[-4:], 16)
        elif self.targetDevice == WAGO:
            _blockStartAddress = _state.solver.eval(_state.regs.ip)
            _blockEndAddress = _block.instruction_addrs[-1]
            _lastInstruction = _state.solver.eval(_state.mem[_blockEndAddress].uint32_t.resolved)
        _firstInstruction = _state.solver.eval(_state.mem[_blockStartAddress].uint32_t.resolved)

        # Corresponds to orr lr, lr, #1 (0xe01f04e) 
        if self.targetDevice == BBB:
            if (_firstInstruction == 235008078 or int('0x' + self.get_32_bit_address(_firstInstruction)[-4:], 16) == 46464) and _blockStartAddress != self.codesysConnector.mappedAppAddress:
                self.functionCounter += 1
                self.currentFunctionCounter = self.functionCounter
                self.currentFunctionStack.append(self.functionCounter)

                # Enable read after the first block
                print('* Detected funtion prologue: {} - {}...'.format(hex(_blockStartAddress), self.functionCounter))

            if _firstInstruction == 235008078:
                self.currentCodesysStackReg = _state.solver.eval(_state.regs.r13) - 0x8
                print('* Considered R7 {} ...'.format(hex(self.currentCodesysStackReg)))
        # Function Start: 0x00442de9     Function End: 0x10402DE9
        elif self.targetDevice == WAGO:
            if (_firstInstruction == 3912057856 or _firstInstruction == 3912056848) and _blockStartAddress != self.codesysConnector.mappedAppAddress:
                self.functionCounter += 1
                self.currentFunctionCounter = self.functionCounter
                self.currentFunctionStack.append(self.functionCounter)

                # Enable read after the first block
                print('* Detected funtion prologue: {} - {}...'.format(hex(_blockStartAddress), self.functionCounter))

            if _firstInstruction == 3912057856:
                self.currentCodesysStackReg = _state.solver.eval(_state.regs.r13) - 0x8
                print('* Considered SL (R10) {} ...'.format(hex(self.currentCodesysStackReg)))

        if self.nextBlockReCalculate and self.currentFunctionStack:
            self.currentFunctionStack.pop()

            if len(self.currentFunctionStack) == 0:
                self.disableWriteTracker = True
                self.disableReadTracker = True
            else:
                self.currentFunctionCounter = self.currentFunctionStack[-1]

            self.nextBlockReCalculate = False
            if _blockStartAddress >= self.codesysConnector.mappedStartAddress and _blockStartAddress < self.codesysConnector.mainTaskMapEndAddress:
                if self.targetDevice == BBB:
                    self.currentCodesysStackReg = _state.solver.eval(_state.regs.r7)
                    print('* Modified R7 {} ...'.format(hex(self.currentCodesysStackReg)))
                elif self.targetDevice == WAGO:
                    self.currentCodesysStackReg = _state.solver.eval(_state.regs.r10)
                    print('* Modified SL (R10) {} ...'.format(hex(self.currentCodesysStackReg)))

        if self.targetDevice == BBB and _lastInstruction == 48512:
            self.nextBlockReCalculate = True
            print('* Detected library function epilogue (0xBD80) - {} ...'.format(self.currentFunctionCounter))
        #elif self.targetDevice == WAGO and (_lastInstruction == 3904733200 or _lastInstruction == 3904734208):
        elif self.targetDevice == WAGO and (_lastInstruction == 3904733200):
            self.nextBlockReCalculate = True
            print('* Detected library function epilogue - {} ...'.format(self.currentFunctionCounter))

    def enable_safe_write_tracking(self):
        print('[*] Enabling safe write tracking ...')
        self.simulationState.inspect.b('mem_write', when = angr.BP_AFTER, action = self.store_safe_write_state)

    def store_safe_write_state(self, _state):
        _intraStackFrameWriteOffset = self.currentCodesysStackReg - _state.solver.eval(_state.inspect.mem_write_address)

        if self.experimentType == CLEAN_EXPERIMENT and not self.disableWriteTracker:
            if not self.currentFunctionCounter in self.cleanWriteTracker:
                self.cleanWriteTracker[self.currentFunctionCounter] = [_intraStackFrameWriteOffset]
            elif _intraStackFrameWriteOffset not in self.cleanWriteTracker[self.currentFunctionCounter]:
                    self.cleanWriteTracker[self.currentFunctionCounter].append(_intraStackFrameWriteOffset)
        elif self.experimentType == VULNERABLE_EXPERIMENT and not self.disableWriteTracker:
            if self.currentFunctionCounter in self.cleanWriteTracker:
                if not _intraStackFrameWriteOffset in self.cleanWriteTracker[self.currentFunctionCounter]:
                    self.post_oob_write(_state)
    
    def retrieve_tracked_intra_stack_frame_writes(self):
        print('\n[*] Retrieved tracked intra-stack frame writes ...\n')
        return self.cleanWriteTracker

    def enable_safe_read_tracking(self):
        print('[*] Enabling safe read tracking ...')
        self.simulationState.inspect.b('mem_read', when = angr.BP_AFTER, action = self.store_safe_read_state)

    def store_safe_read_state(self, _state):
        _intraStackFrameReadOffset = self.currentCodesysStackReg - _state.solver.eval(_state.inspect.mem_read_address)
        _instructionAddress = _state.scratch.ins_addr

        if not _instructionAddress:
            return

        insns = self.simulationProject.factory.block(_state.addr, backup_state = _state).capstone.insns
        for _instruction in insns:
            _operand2 = None

            if _instruction.address == _instructionAddress and len(_instruction.operands) >= 2:
                _operand2 = _instruction.reg_name(_instruction.operands[1].reg)
                break

        if not _operand2 or _operand2 == 'pc':
            return

        if self.experimentType == CLEAN_EXPERIMENT and not self.disableReadTracker:
            if not self.currentFunctionCounter in self.cleanReadTracker:
                self.cleanReadTracker[self.currentFunctionCounter] = [_intraStackFrameReadOffset]
            elif _intraStackFrameReadOffset not in self.cleanReadTracker[self.currentFunctionCounter]:
                    self.cleanReadTracker[self.currentFunctionCounter].append(_intraStackFrameReadOffset)
        elif self.experimentType == VULNERABLE_EXPERIMENT and not self.disableReadTracker:
            if self.currentFunctionCounter in self.cleanReadTracker:
                if not _intraStackFrameReadOffset in self.cleanReadTracker[self.currentFunctionCounter]:
                    self.post_oob_read(_state)

    def retrieve_tracked_intra_stack_frame_reads(self):
        print('\n[*] Retrieved tracked intra-stack frame reads ...\n')
        return self.cleanReadTracker

    # Save simulation stack for block state tracking
    def enable_block_stack_tracking(self):
        print('[*] Enabling block stack history ...')
        self.simulationStackEnabled = True
        self.simulationState.inspect.b('irsb', when = angr.BP_BEFORE, action = self.push_block_state)

    def check_function_start(self, _state):
        _blockStartAddress = 0
        if self.targetDevice == BBB:
            _blockStartAddress = _state.solver.eval(_state.regs.ip) - 0x1
        elif self.targetDevice == WAGO:
            _blockStartAddress = _state.solver.eval(_state.regs.ip)

        _firstInstruction = _state.solver.eval(_state.mem[_blockStartAddress].uint32_t.resolved)
        
        # Corresponds to orr lr, lr, #1 (0xe01f04e)
        if ((self.targetDevice == BBB and _firstInstruction == 235008078) or (self.targetDevice == WAGO and _firstInstruction == 3912057856)) and _blockStartAddress != self.codesysConnector.mappedAppAddress:

            # Check if the block is counted
            if _blockStartAddress not in self.stackObj.iecFunctionAddressList:
                self.stackObj.iecFunctionAddressList.append(_blockStartAddress)
                
            print('* Detected funtion prologue - {} ...'.format(len(self.stackObj.iecFunctionAddressList)))

            # Enable graph generation from PLC_PRG
            if self.detectedPlcPrg: ###
                self.detectedNextFunction = True ###
            self.detectedPlcPrg = True ###

            return True
        return False

    def get_32_bit_address(self, _address):
        return '0x' + ('0' * (8 - len(hex(_address)[2:]))) + hex(_address)[2:]

    def detect_library_function_start(self, _state):
        _blockStartAddress = 0
        _block = self.simulationProject.factory.block(_state.addr, backup_state = _state)
        if self.targetDevice == BBB:
            _blockStartAddress = _state.solver.eval(_state.regs.ip) - 0x1
            _firstInstruction = int('0x' + self.get_32_bit_address(_state.solver.eval(_state.mem[_blockStartAddress].uint32_t.resolved))[-4:], 16)
            _lastInstruction = int('0x' + self.get_32_bit_address(_state.solver.eval(_state.mem[_block.instruction_addrs[-1]-1].uint32_t.resolved))[-4:], 16)
        elif self.targetDevice == WAGO:
            _blockStartAddress = _state.solver.eval(_state.regs.ip)
            _firstInstruction = _state.solver.eval(_state.mem[_blockStartAddress].uint32_t.resolved)
            _lastInstruction = _state.solver.eval(_state.mem[_block.instruction_addrs[-1]].uint32_t.resolved)
        
        # Instruction: push {r7, lr} (0xB580)
        if (self.targetDevice == BBB and _firstInstruction == 46464) or (self.targetDevice == WAGO and _firstInstruction == 3912056848) and _blockStartAddress != self.codesysConnector.mappedAppAddress:
            print('* Detected library function prologue ...')
            self.perFunctionStoreGraph = Graph()
        
        if (self.targetDevice == BBB and _lastInstruction == 48512) or (self.targetDevice == WAGO and _lastInstruction == 3904733200):
            print('* Detected library function epilogue ...')
            self.perFunctionStoreGraph = None

    def push_block_state(self, _state):
        _blockStartAddress = _state.solver.eval(_state.inspect.address)
        _ifFunctionPrologue = self.check_function_start(_state)
        self.detect_library_function_start(_state)

        _block = self.simulationProject.factory.block(_state.addr, backup_state = _state)
        if _blockStartAddress >= self.codesysConnector.mappedStartAddress and _blockStartAddress < self.codesysConnector.mainTaskMapEndAddress and self.detectedPlcPrg:
            _blockEndAddress = _block.instruction_addrs[-1]
            self.stackObj.push(_blockStartAddress, _state, _blockEndAddress, _ifFunctionPrologue)

        # This handles vulnerable program hexdumps that do not end the simulation
        if self.targetDevice == WAGO and _state.solver.eval(_state.mem[_block.instruction_addrs[-1]].uint32_t.resolved) == 0:
            self.simulationEnd = True

    # Generating store load graph for identifying patch location (code cave hook location)
    def enable_store_load_tracking(self, _forceEnableGraphCreation = False):
        self.forceEnableGraphCreation = _forceEnableGraphCreation
        self.simulationState.inspect.b('mem_write', when = angr.BP_BEFORE, action = self.add_store_node)
        self.simulationState.inspect.b('mem_read', when = angr.BP_AFTER, action = self.add_load_node)
        self.simulationState.inspect.b('reg_write', when = angr.BP_BEFORE, action = self.add_transition_node)

    def get_register_name(self, _regName):
        _regNameDict = { 'sb':'r9', 'sl':'r10', 'fp':'r11', 'ip':'r12', 'sp':'r13', 'lr':'r14'}
        if _regName in _regNameDict:
            return _regNameDict[_regName]
        return _regName

    def add_transition_node(self, _state):
        if (self.detectedPlcPrg and self.detectedNextFunction) or self.forceEnableGraphCreation: ###
            # Use state.scratch.ins_addr to get the current instruction pointer.
            _instructionAddress = _state.scratch.ins_addr
            insns = self.simulationProject.factory.block(_state.addr, backup_state = _state).capstone.insns
            _bbbRegisterList = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14']
            _wagoRegisterList = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'pc']

            for _instruction in insns:
                _operand2 = None

                if len(_instruction.operands) == 3:
                    if _instruction.reg_name(_instruction.operands[0].reg) == _instruction.reg_name(_instruction.operands[1].reg):
                        _operand2 = self.get_register_name(_instruction.reg_name(_instruction.operands[2].reg))
                    else:
                        _operand2 = self.get_register_name(_instruction.reg_name(_instruction.operands[1].reg))

                if _instruction.address == _instructionAddress and _operand2 and ((self.targetDevice == BBB and _operand2 in _bbbRegisterList) or (self.targetDevice == WAGO and _operand2 in _wagoRegisterList)):
                    _operand1 = _instruction.reg_name(_instruction.operands[0].reg)
                    #print("add_transition_node\t{}:\t{}\t{}".format(hex(_instruction.address), _instruction.mnemonic, _instruction.op_str))

                    if (self.targetDevice == BBB and _operand1 in _bbbRegisterList) or (self.targetDevice == WAGO and _operand1 in _wagoRegisterList):

                        if 'mov' in _instruction.mnemonic:
                            self.loadStoreGraph.add_transition_node(_instructionAddress, _operand1, _operand2, MOV_INSTUCTION, _debug = False)

                        elif 'sub' in _instruction.mnemonic:
                            self.loadStoreGraph.add_transition_node(_instructionAddress, _operand1, _operand2, SUB_INSTRUCTION, _debug = False)

                        elif 'add' in _instruction.mnemonic:
                            self.loadStoreGraph.add_transition_node(_instructionAddress, _operand1, _operand2, ADD_INSTRUCTION, _debug = False)

    def add_store_node(self, _state):
        if (self.detectedPlcPrg and self.detectedNextFunction) or self.forceEnableGraphCreation: ###
            # Use state.scratch.ins_addr to get the current instruction pointer.
            _instructionAddress = _state.scratch.ins_addr
            _writeAddress = _state.solver.eval(_state.inspect.mem_write_address)
            _writeData = _state.solver.eval(_state.inspect.mem_write_expr)
            insns = self.simulationProject.factory.block(_state.addr, backup_state = _state).capstone.insns
            for _instruction in insns:
                if _instruction.address == _instructionAddress and ('str' in _instruction.mnemonic or 'stm' in _instruction.mnemonic):
                    #print("add_store_node\t{}:\t{}\t{}".format(hex(_instruction.address), _instruction.mnemonic, _instruction.op_str))
                    self.loadStoreGraph.add_store_node(_instructionAddress, self.get_register_name(_instruction.reg_name(_instruction.operands[0].reg)), _writeAddress, _writeData, _debug = False)

                    if self.perFunctionStoreGraph:
                        self.perFunctionStoreGraph.add_store_node(_instructionAddress, _instruction.reg_name(_instruction.operands[0].reg), _writeAddress, _writeData, _debug = False)

    def add_load_node(self, _state):
        if (self.detectedPlcPrg and self.detectedNextFunction) or self.forceEnableGraphCreation: ###
            # Use state.scratch.ins_addr to get the current instruction pointer.
            _instructionAddress = _state.scratch.ins_addr
            _readAddress = _state.solver.eval(_state.inspect.mem_read_address)
            _readData = _state.solver.eval(_state.inspect.mem_read_expr)
            insns = self.simulationProject.factory.block(_state.addr, backup_state = _state).capstone.insns
            for _instruction in insns:
                if _instruction.address == _instructionAddress and 'ldr' in _instruction.mnemonic:
                    #print("add_load_node\t{}:\t{}\t{}".format(hex(_instruction.address), _instruction.mnemonic, _instruction.op_str))
                    self.loadStoreGraph.add_load_node(_instructionAddress, self.get_register_name(_instruction.reg_name(_instruction.operands[0].reg)), self.get_register_name(_instruction.reg_name(_instruction.operands[1].reg)), _readAddress, _readData, _debug = False)
                if _instruction.address == _instructionAddress and 'ldm' in _instruction.mnemonic:
                    #print("add_load_node\t{}:\t{}\t{}".format(hex(_instruction.address), _instruction.mnemonic, _instruction.op_str))
                    _operand2Count = len(_instruction.operands) - 1
                    _regIndex = 1

                    while _regIndex <= _operand2Count:
                        _operand1 = _instruction.reg_name(_instruction.operands[_regIndex].reg)
                        _readAddress = _readAddress + ((_regIndex - 1) * 4)
                        _readData = 0 # This is not the actual value.
                        self.loadStoreGraph.add_load_node(_instructionAddress, _operand1, None, _readAddress, _readData, _debug = False)
                        _regIndex += 1

    # Get vulnerability information
    def get_vulnerability_information(self, _state):
        if self.vulnerabilityType != OS_COMMAND_INJECTION:
            _vulnerabilityObj = self.VulnerabilityInformation(self.codesysConnector.mappedAppAddress, self.vulnerabilityOperatedAddress, self.vulnerabilityOperatedExpression, self.vulnerabilityType, self.stackObj.get_previous_caller_function_state())
            self.vulnerabilityList.append(_vulnerabilityObj)
            _exploitInformation = self.exploit_localization(self.get_exploit_localization_start_node(_state))
            
            index = 0
            if len(_exploitInformation) > 1:
                index = int(input('* Enter the index of selected vulnerability information: '))

            _exploitInstructionLocation, _exploitMemoryLocation, _exploitMemoryValue, _completeLocationMemoryContent, _ifMissingTransitionFunction = _exploitInformation[index]
            print('* Selected vulnerability location is {} ...'.format(hex(_exploitInstructionLocation)))
            print('* Exploit memory location is {} ...'.format(hex(_exploitMemoryLocation)))
        else:
            _vulnerabilityObj = self.VulnerabilityInformation(self.codesysConnector.mappedAppAddress, self.vulnerabilityOperatedAddress, self.vulnerabilityOperatedExpression, self.vulnerabilityType, self.stackObj.stack[-1])
            self.vulnerabilityList.append(_vulnerabilityObj)
            _exploitInstructionLocation, _exploitMemoryLocation, _exploitMemoryValue, _completeLocationMemoryContent, _ifMissingTransitionFunction = self.simple_exploit_localization()

        _vulnerabilityObj.initialize_exploit_information(_exploitInstructionLocation, _exploitMemoryLocation, _exploitMemoryValue, self.vulnerabilitySuggestedSize, _completeLocationMemoryContent, _ifMissingTransitionFunction)

    def simple_exploit_localization(self):
        _state = self.vulnerabilityState
        _exploitInstructionLocation = _state.scratch.ins_addr
        
        # Time
        start = time.time()

        insns = self.simulationProject.factory.block(_state.addr, backup_state = _state).capstone.insns
        for _instruction in insns:
            if _instruction.address == _exploitInstructionLocation:
                _operand3 = re.search('\[(.+?)\]', _instruction.op_str).group(1).split()[-1]
                break

        _exploitMemoryValue = self.registerObj.get_by_name(_operand3, _state)
        _exploitMemoryLocation = 0
        _completeLocationMemoryContent = 0
        _ifMissingTransitionFunction = False

        # Time
        print('[*] Time for localizing vulnerability: ' + str(time.time() - start))

        print('\n[*] Detected exploit location: {}'.format(hex(_exploitInstructionLocation)))
        print('[*] Detected exploit input: {} ({})'.format(_exploitMemoryValue, hex(_exploitMemoryValue)))

        return _exploitInstructionLocation, _exploitMemoryLocation, _exploitMemoryValue, _completeLocationMemoryContent, _ifMissingTransitionFunction 

    # Custom memory bound violation rule
    def check_read_instructions(self, _state, _address):
        insns = self.simulationProject.factory.block(_state.addr, backup_state = _state).capstone.insns
        for _instruction in insns:
            if _instruction.address == _address and ('ldr' in _instruction.mnemonic or 'ldm' in _instruction.mnemonic):
                #print('{} {}'.format(_instruction.mnemonic, hex(_instruction.address)))
                return True
            else:
                return False

    def enable_custom_memory_rule(self, custom_rule):
        print('[*] Enabling rule-based custom memory vulnerability detection ...')
        self.customRuleObj.parse(custom_rule)

        if self.customRuleObj.rule_type == OOB_READ:
            self.simulationState.inspect.b('mem_read', when = angr.BP_AFTER, condition = self.check_memory_violation, action = self.post_memory_violation)
        else:
            self.simulationState.inspect.b('mem_write', when = angr.BP_AFTER, condition = self.check_memory_violation, action = self.post_memory_violation)

    def process_eval_condition(self, _checkAddress, _codesysStackReg):
        if "WRITE_ADDRESS" in self.customRuleObj.eval_condition:
            self.customRuleObj.eval_condition = self.customRuleObj.eval_condition.replace("WRITE_ADDRESS", hex(_checkAddress))
        elif "READ_ADDRESS" in self.customRuleObj.eval_condition:
            self.customRuleObj.eval_condition = self.customRuleObj.eval_condition.replace("READ_ADDRESS", hex(_checkAddress))

        if "CODESYS_STACK" in self.customRuleObj.eval_condition:
            self.customRuleObj.eval_condition = self.customRuleObj.eval_condition.replace("CODESYS_STACK", hex(_codesysStackReg))
        if "CODESYS_TEXT" in self.customRuleObj.eval_condition:
            self.customRuleObj.eval_condition = self.customRuleObj.eval_condition.replace("CODESYS_TEXT", hex(self.codesysConnector.mappedAppAddress))
        if "CODESYS_DATA" in self.customRuleObj.eval_condition:
            self.customRuleObj.eval_condition = self.customRuleObj.eval_condition.replace("CODESYS_DATA", hex(self.codesysConnector.dataSectionStartAddress))
        if "CODESYS_ADDRESS_TABLE" in self.customRuleObj.eval_condition:
            self.customRuleObj.eval_condition = self.customRuleObj.eval_condition.replace("CODESYS_ADDRESS_TABLE", hex(self.jumpTableBaseAddress))

        self.customRuleObj.eval_condition = self.customRuleObj.eval_condition.lower()

    def check_memory_violation(self, _state):
        self.customRuleObj.eval_condition = self.customRuleObj.original_eval_condition
        _instructionAddress = _state.scratch.ins_addr

        if not _instructionAddress or not self.simulationStackEnabled or not self.stackObj.stack or not self.detectedPlcPrg:
            return False

        if not self.stackObj.stack:
            return False

        if self.customRuleObj.rule_type == OS_COMMAND_INJECTION and not self.calculatedJumpTableBaseAddress:
            return False
        
        if self.customRuleObj.rule_type == OOB_READ and not self.check_read_instructions(_state, _instructionAddress):
            return False

        _checkAddress = None
        _isExecutingWithinContext = False

        if ((self.customRuleObj.rule_type == OOB_WRITE or self.customRuleObj.rule_type == IMPROPER_INPUT_VALIDATION) and (_instructionAddress < self.codesysConnector.mappedAppAddress or _instructionAddress >= self.codesysConnector.mainTaskMapEndAddress)) or ((self.customRuleObj.rule_type == OS_COMMAND_INJECTION) and (_instructionAddress > self.codesysConnector.mappedAppAddress or _instructionAddress <= self.codesysConnector.mainTaskMapEndAddress)):
            _checkAddress = _state.solver.eval(_state.inspect.mem_write_address)
            _isExecutingWithinContext = True
        elif (self.customRuleObj.rule_type == OOB_READ) and (_instructionAddress < self.codesysConnector.mappedAppAddress or _instructionAddress >= self.codesysConnector.mainTaskMapEndAddress):
            _checkAddress = _state.solver.eval(_state.inspect.mem_read_address)
            _isExecutingWithinContext = True

        if _isExecutingWithinContext:
            _counter, _startAddress, _task_state, _endAddress, _ifFunctionPrologue, _ifVulnerable = self.stackObj.get_caller_function_state()
            _codesysStackReg = _task_state.solver.eval(_task_state.regs.r13) - 0x8 
            print('* ({}) Considered codesys stack register: {} while writing/reading at {} ...'.format(hex(_instructionAddress), hex(_codesysStackReg), hex(_checkAddress)))

            self.process_eval_condition(_checkAddress, _codesysStackReg)
            try:
                if eval(self.customRuleObj.eval_condition):
                    self.runtimeBoundaryAddress = _codesysStackReg
                    return True
            except:
                print("[X] Error in evaluating vulnerability detection rule.")

        return False

    def post_memory_violation(self, _state):
        if self.vulnerabilityDetected:
            return

        _exploitMemAddress = 0
        _length = 0
        _expression = 0
        _instructionAddress = _state.scratch.ins_addr

        if self.customRuleObj.rule_type == OOB_READ:
            _exploitMemAddress = _state.solver.eval(_state.inspect.mem_read_address)
            _length = _state.inspect.mem_read_length
            _expression = hex(_state.solver.eval(_state.inspect.mem_read_expr))
        else:
            _exploitMemAddress = _state.solver.eval(_state.inspect.mem_write_address)
            _length = _state.inspect.mem_write_length
            _expression = hex(_state.solver.eval(_state.inspect.mem_write_expr))

        self.registerObj.update_state(_state)
        self.memoryObj.update_state(_state)

        print('\n***************************')
        print("RULE: {}".format(self.customRuleObj.rule_name))
        print("MESSAGE: {}".format(self.customRuleObj.message))
        print("***************************")
        self.print_block(_state)
        print('------ DEBUG INFO ------')

        print('* Instruction Address: ', hex(_instructionAddress))
        print('* Exploit Memory Address: ', hex(_exploitMemAddress))
        print('* Length: ', _length)
        print('* Expression: ', _expression)

        # Get vulnerability information
        self.vulnerabilityState = copy.deepcopy(_state)
        self.vulnerabilityInsAddress = _instructionAddress
        self.vulnerabilityOperatedAddress = _exploitMemAddress
        self.vulnerabilityOperatedExpression = _expression
        self.vulnerabilityType = self.customRuleObj.rule_type

        # Handling simulation state
        if self.customRuleObj.rule_action == RULE_ALERT:
            self.simulationEnd = True
            self.vulnerabilityDetected = True

    # OS Command Injection
    def enable_jump_table_address_detection(self):
        print('[*] Enabling jump table start address detection ...')
        self.simulationState.inspect.b('irsb', when = angr.BP_BEFORE, action = self.post_jump_table_address_detection)

    def search_jump_table_base_address(self, _state, _jumpTableSearchStartAddress):
        _currentAddress = _jumpTableSearchStartAddress
        _emptyMemCounter = 0
        _lastNonEmptyAddress = 0

        while _emptyMemCounter < 10:
            _checkMemValue = struct.unpack("<I", struct.pack(">I", _state.solver.eval(_state.memory.load(_currentAddress, 0x4))))[0]
            
            if _checkMemValue == 0:
                _emptyMemCounter += 1
            else:
                _lastNonEmptyAddress = _currentAddress
                _emptyMemCounter = 0

            _currentAddress -= 0x4

        print('[*] Detected the jump table base address at {} ...'.format(hex(_lastNonEmptyAddress)))
        self.calculatedJumpTableBaseAddress = True
        self.jumpTableBaseAddress = _lastNonEmptyAddress
        
    def post_jump_table_address_detection(self, _state):
        if self.calculatedJumpTableBaseAddress:
            return

        if not self.detectedJumpTableBranch:
            _block = self.simulationProject.factory.block(_state.addr, backup_state = _state)
            _lastInstructionAddress = _block.instruction_addrs[-1]

            insns = self.simulationProject.factory.block(_state.addr, backup_state = _state).capstone.insns
            for _instruction in insns:

                if _instruction.address == _lastInstructionAddress:
                    _operand1 = _instruction.reg_name(_instruction.operands[0].reg)

                    if self.targetDevice == BBB and 'blx' in _instruction.mnemonic and _operand1 == 'r4':
                        self.detectedJumpTableBranch = True
                    elif self.targetDevice == WAGO and 'mov' in _instruction.mnemonic and _operand1 == 'pc':
                        self.detectedJumpTableBranch = True
        else:
            if self.targetDevice == BBB:
                _jumpTableSearchStartAddress = _state.solver.eval(_state.regs.r6)
            if self.targetDevice == WAGO:
                _jumpTableSearchStartAddress = _state.solver.eval(_state.regs.r11)
            self.search_jump_table_base_address(_state, _jumpTableSearchStartAddress)

    # Hackly function for finding start node to perform graph traversal
    def get_exploit_localization_start_node(self, _state):
        _startNodeList = []

        if self.vulnerabilityType == OOB_READ:
            insns = self.simulationProject.factory.block(_state.addr, backup_state = _state).capstone.insns
            for index in range(0, len(insns)-1):
                if self.vulnerabilityInsAddress == insns[index].address and 'ldr' in insns[index].mnemonic:
                    _startNodeList.append(insns[index].address)
                    print('* Found read specific start node: {} ...'.format(hex(_startNodeList[-1])))
                    break

        if self.vulnerabilityType == OOB_WRITE or self.vulnerabilityType == OOB_READ:
            insns = self.simulationProject.factory.block(_state.addr, backup_state = _state).capstone.insns
            for index in range(len(insns)-1, -1, -1):
                if 'cmp' in insns[index].mnemonic or 'sub' in insns[index].mnemonic or 'tst' in insns[index].mnemonic:
                    _startNodeList.append(self.loadStoreGraph.get_reg_state_value(insns[index].reg_name(insns[index].operands[0].reg)))
                    print('* Found start node: {} ...'.format(hex(_startNodeList[-1])))
                    break

        return _startNodeList

    # Exploit localization using DFS graph traversal
    def get_neighbors(self, _graph, _nodeLabel):
        return list(_graph.predecessors(_nodeLabel))

    def get_successors(self, _graph, _nodeLabel):
        return list(_graph.successors(_nodeLabel))

    def check_if_address_in_range(self, _address, _startAddress, _endAddress):
        if _startAddress <= int(_address, 16) <= _endAddress:
            return True
        return False

    def dfs(self, _visited, _graph, _nodeLabel, _startAddress, _endAddress, _debug = False):
        if _nodeLabel not in _visited:
            if self.check_if_address_in_range(_nodeLabel, _startAddress, _endAddress) and _graph.nodes[_nodeLabel]['operation_type'] == STR_INSTRUCTION and _graph.nodes[_nodeLabel]['operand1'] in ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14']:
                self.faultAddressList.append([int(_nodeLabel, 16), _graph.nodes[_nodeLabel]])
            
            if _debug:
                print(_nodeLabel, ':', _graph.nodes[_nodeLabel], self.check_if_address_in_range(_nodeLabel, _startAddress, _endAddress))

            _visited.append(_nodeLabel)
            for predecessor in self.get_neighbors(_graph, _nodeLabel):
                self.dfs(_visited, _graph, predecessor, _startAddress, _endAddress)

    def get_start_end_address(self):
        _counter, _startAddress, _callerState, _endAddress, _ifFunctionPrologue, _ifVulnerable = self.stackObj.get_previous_caller_function_state()
        _callerBlock = self.simulationProject.factory.block(_callerState.addr, backup_state = _callerState)
        _startInstructionAddress = _callerBlock.instruction_addrs[0]
        _endInstructionAddress = _callerBlock.instruction_addrs[-1]

        return _startInstructionAddress, _endInstructionAddress, self.stackObj.ifMissingTransitionFunction

    def suggest_exploit_location(self, _graph):
        _faultAddress, _faultNode = max(self.faultAddressList)
        _faultState = self.stackObj.get_corresponding_state(_faultAddress, self.simulationProject)
        _faultBlock = self.simulationProject.factory.block(_faultState.addr, backup_state = _faultState)
        
        # This appraoch fails when angr misbehaves and cannot fetch the proper block (ex: desalination improper input)
        for _instruction in _faultBlock.capstone.insns:
            if _instruction.address == _faultAddress:
                _exploitInstructionLocation = _instruction.address
                _exploitMemoryLocation = int(self.get_successors(_graph, hex(_faultAddress))[0], 16)
                _exploitMemoryValue = _graph.nodes[self.get_successors(_graph, hex(_faultAddress))[0]]['value']
                _completeLocationMemoryContent = struct.unpack("<I", struct.pack(">I", self.vulnerabilityState.solver.eval(self.vulnerabilityState.memory.load(_exploitMemoryLocation, 0x4))))[0]

                print('[*] Detected exploit location: {}: {} {}'.format(hex(_exploitInstructionLocation), _instruction.mnemonic, _instruction.op_str))
                print('[*] Detected exploit input: {}: {}'.format(hex(_exploitMemoryLocation), _exploitMemoryValue))
                print('[*] Mermory value at exploit location: {}: {}'.format(hex(_exploitMemoryLocation), self.get_32_bit_address(_completeLocationMemoryContent)))
                return _exploitInstructionLocation, _exploitMemoryLocation, _exploitMemoryValue, _completeLocationMemoryContent

    def exploit_localization(self, _localizationStartAddressList):
        _exploitInformation = []
        _counter = 0

        # Time
        start = time.time()

        print('- Localization start address list: {} ...'.format(_localizationStartAddressList))
        for _localizationStartAddress in _localizationStartAddressList:
            visited = []
            print('----------{}----------'.format(_counter))
            print('[*] Starting exploit localization from address %s ...'%(hex(_localizationStartAddress)))
            _startAddress, _endAddress, _ifMissingTransitionFunction = self.get_start_end_address()
            print('[*] Start address: {} End Address: {}...'.format(hex(_startAddress), hex(_endAddress)))
            self.dfs(visited, self.loadStoreGraph.graph, hex(_localizationStartAddress), _startAddress, _endAddress)
            print('[*] Bounded by %s - %s ...' %(hex(_startAddress), hex(_endAddress)))

            if len(self.faultAddressList) == 0:
                print('[*] Search unsuccessful for start node {} ...'.format(hex(_localizationStartAddress)))
                _counter += 1
                continue
            else:
                print('[*] Search successful for start node {} ...'.format(hex(_localizationStartAddress)))

            _exploitInstructionLocation, _exploitMemoryLocation, _exploitMemoryValue, _completeLocationMemoryContent = self.suggest_exploit_location(self.loadStoreGraph.graph)
            print('----------{}----------\n'.format(_counter))
            _counter += 1
            _exploitInformation.append([_exploitInstructionLocation, _exploitMemoryLocation, _exploitMemoryValue, _completeLocationMemoryContent, _ifMissingTransitionFunction])
        
        # Time
        print('[*] Time for localizing vulnerability: ' + str(time.time() - start))
        
        return _exploitInformation

    # Vulnerability helper functions
    def if_vulnerability_remain(self):
        if len(self.vulnerabilityList) > 0:
            return True
        else:
            return False

    def get_top_vulnerability_object(self):
        return self.vulnerabilityList.pop()