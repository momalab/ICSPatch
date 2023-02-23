import ctypes
from ctypes import *  # module for C data types
import sys  # module for system specific parameters and functions
import os

import time
from timeit import default_timer as timer
import subprocess
import psutil
import configparser

import paramiko
from scp import SCPClient

# OK error code
T32_OK = 0

# Error codes
WIN_MESSAGEMODENONE = 0x00
WIN_MESSAGEMODEINFO = 0x01
WIN_MESSAGEMODEERROR = 0x02
WIN_MESSAGEMODESTATE = 0x04
WIN_MESSAGEMODEWARNINFO = 0x08
WIN_MESSAGEMODEERRORINFO = 0x10
WIN_MESSAGEMODETEMP = 0x20
WIN_MESSAGEMODETEMPINFO = 0x40

# multipleInstances to True for using custom port. It is assumed that the T32 software is configured already
class Lauterbach:
    def __init__(self, multipleInstances=False, T32_PORT = '', configPath='config/lauterbach/lauterbach_config.conf'):
        self.T32_PATH = ''
        self.T32_CONFIG_PATH = ''
        self.T32_STARTUP_PATH = ''

        self.T32_NODE = ''
        self.T32_PORT = T32_PORT
        self.T32_PACKLEN = ''

        self.T32API = None
        self.T32_DEV = 0
        self.VERBOSE = 0

        self.DEVICE_USERNAME = ''
        self.DEVICE_IP_ADDRESS = ''
        self.DEVICE_PASSWORD = ''

        self.Initialize(multipleInstances, configPath)
        
    ### General Helper Modules ###

    def Initialize(self, multipleInstances, configPath):
        configReader = configparser.ConfigParser()
        configReader.read(configPath)

        self.T32_PATH = configReader.get('TRACE32', 'T32_PATH')
        self.T32_CONFIG_PATH = configReader.get('TRACE32', 'T32_CONFIG_PATH')
        self.T32_STARTUP_PATH = configReader.get('TRACE32', 'T32_STARTUP_PATH')

        if not multipleInstances:
            self.T32_PORT = configReader.get('API_COMMUNICATION', 'T32_PORT')

        self.T32_PACKLEN = configReader.get('API_COMMUNICATION', 'T32_PACKLEN')
        self.T32_NODE = configReader.get('API_COMMUNICATION', 'T32_NODE')

        self.T32API = ctypes.CDLL(configReader.get('LAUTERBACH_WRAPPER', 'T32API_PATH'))
        self.T32_DEV = int(configReader.get('LAUTERBACH_WRAPPER', 'T32_DEV'))
        self.VERBOSE = int(configReader.get('LAUTERBACH_WRAPPER', 'VERBOSE'))

        self.DEVICE_USERNAME = configReader.get('DEVICE_SSH', 'DEVICE_USERNAME')
        self.DEVICE_IP_ADDRESS = configReader.get('DEVICE_SSH', 'DEVICE_IP_ADDRESS')
        self.DEVICE_PASSWORD = configReader.get('DEVICE_SSH', 'DEVICE_PASSWORD')

        self.Check_Configuration()

    def Check_Configuration(self):
        if self.T32_PATH == '':
            print('- T32_PATH not specified.')
        elif self.T32_CONFIG_PATH == '':
            print('- T32_CONFIG_PATH not specified.')
        elif self.T32API == None:
            print('- T32API_PATH not specified.')
        elif self.T32_DEV == '':
            print('- T32_DEV not specified.')
        else:
            print('- Wrapper configured successfully.')

    
    def Dec_To_Hex(self, decimal):
        return hex(decimal)
    
    ### T32 Helper modules ###
    
    def Init(self):
        # Initialize the communication channel
        return self.T32API.T32_Init()
            
    def Ping(self):
        # Ping the debug device
        return self.T32API.T32_Ping()
            
    def Attach(self):
        # Connect to the debug device
        return self.T32API.T32_Attach(self.T32_DEV)
    
    def Disconnect(self):
        # Disconnect from the debug device
        if self.T32API.T32_Exit() != T32_OK:
            print('- Failed to close remote connection.')
    
    ### Main modules ###
    
    def Configure(self):
        # Configure communication channel to the TRACE32 device
        # use b for byte encoding of strings
        self.T32API.T32_Config(b"NODE=", self.T32_NODE.encode())
        
        if self.T32API.T32_Config(b"PORT=", self.T32_PORT.encode()) != T32_OK:
            print('- Invalid port number', self.T32_PORT, 'specified.')
            
        self.T32API.T32_Config(b"PACKLEN=", self.T32_PACKLEN.encode())
        
    def Connect(self):
        self.Configure()

        # Establish communication channel
        for i in range(1, 3):
            if self.Init() == T32_OK:
                if self.Attach() == T32_OK:
                    print('- Remote connection established with TRACE32 PowerView.')
                    if self.Ping() == T32_OK:
                        print('- Ping successful to TRACE32 PowerView.')
                    else:
                        print('- Failure to ping TRACE32 PowerView.')
                    break
                else:
                    if i == 1:
                        print('- Remote connection failed once with TRACE32 PowerView.')
                        self.Disconnect()
                    elif i == 2:
                        print('- Remote connection failed twice with TRACE32 PowerView.')
                        print('- Terminating ...')
            else:
                if i == 1:
                    print('- Remote connection initialization failed once with TRACE32 PowerView.')
                    self.Disconnect()
                elif i == 2:
                    print('- Remote connection initialization failed twice with TRACE32 PowerView.') 
                    print('- Terminating ...')

    def Print_Command_Result(self, command):
        # Executes a command in TRACE32.
        command = 'PRINT ' + command
        if len(command) > 2040:
            print('- Failed to send remote command. Command exceeds 2040 characters.')

        msgString = create_string_buffer(50)  # Creates a mutable character buffer. The returned object is a ctypes array of c_char.
        msgType = c_int64(0)  # Represents the C 64-bit signed int datatype.

        if self.T32API.T32_Cmd(command.encode()) == T32_OK:
            if self.T32API.T32_GetMessage(byref(msgString), byref(msgType)) == T32_OK:
                #print("Result: ",msgString.value)
                return msgString.value
            else:
                print('- Failed to query return message.')
                return 0
        else:
            print('- Failed to execute: %s' % command)
            return 0
        
    def Command(self, command):
        # Executes a command in TRACE32.
        if len(command) > 2040:
            print('- Failed to send remote command. Command exceeds 2040 characters.')
            
        msgString = create_string_buffer(50) # Creates a mutable character buffer. The returned object is a ctypes array of c_char.
        msgType = c_int64(0) # Represents the C 64-bit signed int datatype.
        
        if self.VERBOSE == 0:
            if self.T32API.T32_Cmd(command.encode()) != T32_OK: #Encode the command as byte before sending
                print('- Failed to execute: %s' %command)
        else:
            if self.T32API.T32_Cmd(b'PRINT') == T32_OK:
                if self.T32API.T32_Cmd(command.encode()) == T32_OK:  # Encode the command as byte before sending
                    if self.T32API.T32_GetMessage(byref(msgString), byref(msgType)) == T32_OK:
                        if msgType.value < (WIN_MESSAGEMODETEMPINFO << 1):
                            if msgType.value != WIN_MESSAGEMODENONE and not ((len(msgString.value) == 0) and (
                                    msgType.value & (WIN_MESSAGEMODETEMPINFO | WIN_MESSAGEMODETEMP))):
                                if msgType.value & WIN_MESSAGEMODEINFO:
                                    print('- REPLY: Info message:', msgString.value)
                                if msgType.value & WIN_MESSAGEMODESTATE:
                                    print('- REPLY: Status message:', msgString.value)
                                if msgType.value & WIN_MESSAGEMODEWARNINFO:
                                    print('- REPLY: Warning message:', msgString.value)
                                if (msgType.value & WIN_MESSAGEMODEERRORINFO) or (msgType.value & WIN_MESSAGEMODEERROR):
                                    print('- REPLY: Error message:', msgString.value)
                                if (msgType.value & WIN_MESSAGEMODETEMPINFO) or (msgType.value & WIN_MESSAGEMODETEMP):
                                    print('- REPLY: Miscellaneous message: %s' % msgString.value)
                            else:
                                print('- Successfully executed: %s' % command)
                        else:
                            print('- Failed to determine the type of the return message.')
                    else:
                        print('- Failed to query return message.')
                else:
                    print('- Failed to execute: %s' % command)
            else:
                print('- Failed to execute \'T32_Cmd(""PRINT"")')
                
        del(msgString)
        del(msgType)
    
    def CPU_StepMode(self, mode):
        # Executes one step on an emulator or target. The mode parameter controls the stepping mode:
        # 0 : assembler step, 1: HLL step
        # Bit 7 of mode defines step into or step over a function call
        # Example: 0x81 = 10000001, Steps over a function call, halting on the next HLL line.
        if self.T32API.T32_StepMode(mode) != T32_OK:
            print('- T32_StepMode Error')
    
    def CPU_Step(self):
        # Executes one single step (on an emulator or target).
        if self.T32API.T32_Step() != T32_OK:
            print('- T32_Step Error')
                
    ## Special Modules ##

    def CPU_MemAccess(self, mode='DAP'):
        self.Command("SYStem.MemAccess " + mode)

    def CPU_Access(self, mode="Nonstop"):
        self.Command("SYStem.CpuAccess " + mode)
    
    def CPU_Attach(self):
        self.Command("SYStem.Attach")
        
    def CPU_Break(self):
        returnCode = self.T32API.T32_Break()
        if returnCode != T32_OK:
            print('- T32_Break Error')
        elif returnCode == T32_OK and self.VERBOSE:
            print('- CPU execution halted successfully')

    def CPU_Go(self):
        returnCode = self.T32API.T32_Go()
        if returnCode != T32_OK:
            print('- T32_Go Error')
        elif returnCode == T32_OK and self.VERBOSE:
            print('- CPU execution resumed successfully')

    def API_Lock(self, timeout):
        returnCode = self.T32API.T32_APILock(timeout)
        if returnCode != T32_OK:
            print('- T32_APILock Error')
        elif returnCode == T32_OK and self.VERBOSE:
            print('- API lock granted')

    def API_Unlock(self):
        returnCode = self.T32API.T32_APIUnlock()
        if returnCode != T32_OK:
            print('- T32_APILock Error')
        elif returnCode == T32_OK and self.VERBOSE:
            print('- API lock freed')

    def CPU_Reset(self):
        returnCode = self.T32API.T32_ResetCPU()
        if returnCode != T32_OK:
            print('- T32_ResetCPU Error')
        elif returnCode == T32_OK and self.VERBOSE:
            print('- CPU reset successfully')

    '''
    UNKNOWN = -1
    DOWN = 0
    NOACCESS = 1
    HALTED = 2
    RUNNING = 3
    '''
    def CPU_GetState(self):
        state = c_int(-1) # Variable receiving the state information from Lauterbach
        returnCode = self.T32API.T32_GetState(byref(state))
        if returnCode != T32_OK:
            print('- T32_GetState Error')
        elif returnCode == T32_OK and self.VERBOSE:
            print('- State received successfully')

        return state.value

    def T32_Start(self):
        # Start TRACE32 instance
        if self.T32_STARTUP_PATH == '':
            command = [self.T32_PATH, '-c', self.T32_CONFIG_PATH]
        else:
            command = [self.T32_PATH, '-c', self.T32_CONFIG_PATH, '-s', self.T32_STARTUP_PATH]
        process = subprocess.Popen(command)

        # Wait until the TRACE32 instance is started
        time.sleep(5)
        return process

    def T32_Kill(self, PID):
        process = psutil.Process(PID)
        for childProcess in process.children(recursive=True):
            childProcess.kill()
        process.kill()

    def T32_Quit(self):
        self.Command("QUIT")
        self.Disconnect()

    def SSH_Execute(self, command):
        if self.DEVICE_USERNAME == '':
            print('- DEVICE_USERNAME not specified.')
            return
        elif self.DEVICE_IP_ADDRESS == '':
            print('- DEVICE_IP_ADDRESS not specified.')
            return
        elif self.DEVICE_PASSWORD == '':
            print('- DEVICE_PASSWORD not specified.')
            return

        try:
            paramiko.util.log_to_file('ssh.log')
            SSH_CLIENT = paramiko.SSHClient()
            SSH_CLIENT.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            SSH_CLIENT.connect(hostname=self.DEVICE_IP_ADDRESS, username=self.DEVICE_USERNAME, password=self.DEVICE_PASSWORD)
            SSH_STDIN, SSH_STDOUT, SSH_STDERR = SSH_CLIENT.exec_command(command, timeout=10)
            result = SSH_STDOUT.read().decode()
            error = SSH_STDERR.read().decode('utf-8')

            if error:
                print(error)
            else:
                print(result)
            SSH_CLIENT.close()

        except paramiko.ssh_exception.NoValidConnectionsError as exception:
            print(exception)
        except Exception as exception:
            pass
        finally:
            SSH_CLIENT.close()

    #TODO: Check this
    def SCP_Transfer(self, localPath, remotePath):
        if self.DEVICE_USERNAME == '':
            print('- DEVICE_USERNAME not specified.')
            return
        elif self.DEVICE_IP_ADDRESS == '':
            print('- DEVICE_IP_ADDRESS not specified.')
            return
        elif self.DEVICE_PASSWORD == '':
            print('- DEVICE_PASSWORD not specified.')
            return

        try:
            paramiko.util.log_to_file('scp.log')
            SSH_CLIENT = paramiko.SSHClient()
            SSH_CLIENT.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            SSH_CLIENT.connect(hostname=self.DEVICE_IP_ADDRESS, username=self.DEVICE_USERNAME, password=self.DEVICE_PASSWORD)
            with SCPClient(SSH_CLIENT.get_transport()) as scp:
                scp.put(localPath, remotePath)

            SSH_CLIENT.close()

        except paramiko.ssh_exception.NoValidConnectionsError as exception:
            print(exception)
        except Exception as exception:
            pass
        finally:
            SSH_CLIENT.close()

    def T32Server_Start(self):
        self.SSH_Execute('/bin/t32server')

    def Switch_To_RunMode(self):
        self.CPU_MemAccess('GdbMON')
        self.Command('Go.MONitor')

    def Switch_To_StopMode(self):
        self.Command('Break.MONitor')
        self.CPU_MemAccess('Denied')

    def Stop_RunMode(self):
        self.Command('Break.SetMONitor OFF')

    def Load_Process(self, mode, processPath, processName, symbolPath):
        spaceID = ''
        self.Command('TASK.List.tasks')
        if mode == "RUN":
            self.Command('TASK.RUN '+processPath)
        elif mode == "SELECT":
            self.Command('TASK.SELect '+processPath)

        time.sleep(1)
        spaceID = self.Print_Command_Result('TASK.SPACEID("'+processName+'")').decode()
        if spaceID:
            self.Command('Data.LOAD.Elf '+symbolPath+' 0x'+spaceID+':0 /NOCODE /NoClear')
            self.Command('Go main')
            self.Command('Data.List')

    '''
        T32_PRINTCODE_ASCII                        0x41
        T32_PRINTCODE_ASCIIP                       0x42
        T32_PRINTCODE_ASCIIE                       0x43
        T32_PRINTCODE_CSV                          0x44
        T32_PRINTCODE_XML                          0x45
    '''
    def GetWindowContent(self, command, reqBytes, printCode):
        # Return Type: String
        offset = 0
        result = ''
        buffer = (c_byte * reqBytes)()

        self.CPU_Break()
        while True:
            length = self.T32API.T32_GetWindowContent(command.encode(), buffer, reqBytes, offset, printCode)

            if length == -1:
                print("T32_GetWindowContent Error.")
                return None
            if length <= 0:
                break
            offset += length
        self.CPU_Go()

        for i in range(0, reqBytes):
            result += chr(buffer[i])
            if self.VERBOSE:
                print(chr(buffer[i]), end="")

        return result

    def BatchCommands(self, filePath):
        # Module can be used to execute a batch of commands. It can also be use to initialize a jtag connection using a single file.
        with open(filePath) as fp:
            for line in fp:
                command = line.rstrip()
                if command:
                    if self.VERBOSE:
                        print("\nCommand Sent: %s", command)
                    self.Command(command)

    def Run_SetupScript(self, filePath):
        self.BatchCommands(filePath)
            
    def ReadRegisterByName(self, regName):
        # Return Type: INT
        # Read value of any register by name
        regValue = c_uint()
        upperRegValue = c_uint()

        returnCode = self.T32API.T32_ReadRegisterByName(regName.encode(), byref(regValue), byref(upperRegValue))
        if returnCode != T32_OK:
            print('- Register read failed.')
            return None
        elif returnCode == T32_OK and self.VERBOSE:
            print("Value of register", regName, "in INT: ", regValue.value)
            print("Value of register", regName, "in HEX: ", self.Dec_To_Hex(regValue.value))
        return regValue.value

    def ReadPC(self):
        # Return Type: INT
        pcValue = c_uint()

        returnCode = self.T32API.T32_ReadPP(byref(pcValue))
        if returnCode != T32_OK:
            print('- PC read failed.')
            return None
        elif returnCode == T32_OK and self.VERBOSE:
            print("Value of register PC in INT: ", pcValue.value)
            print("Value of register PC in HEX: ", self.Dec_To_Hex(pcValue.value))
        return pcValue.value


    def ReadMultipleRegister(self, mask1=0xffffffff, mask2=0xffffffff):
        # Return Type: LIST(INT)
        regValue = (c_uint * 64)(0)
        result = list()

        returnCode = self.T32API.T32_ReadRegister(mask1, mask2, byref(regValue))
        if returnCode != T32_OK:
            print('- Register read failed.')
            return None

        for i in range(0, 64):
            result.append(regValue[i])

        if returnCode == T32_OK and self.VERBOSE:
            print('- Register Snapshot: \n')
            for i in range(0, 64):
                print(self.Dec_To_Hex(regValue[i]))
        return result

    def RegisterSnapshot(self):
        return self.ReadMultipleRegister()

    def WriteRegisterByName(self, regName, regValue, upperRegValue = 0x0):
        # Write a new value to any register by name
        # For any write function break and resume CPU execution manually
        returnCode = self.T32API.T32_WriteRegisterByName(regName.encode(), regValue, upperRegValue)
        if returnCode != T32_OK:
            print('- Register write failed.')
        elif returnCode == T32_OK and self.VERBOSE:
            print("Value written in register", regName, "in INT: ", regValue.value)
            print("Value written in register", regName, "in HEX: ", self.Dec_To_Hex(regValue.value))

    '''Generically used memory access class values (independent of CPU architecture):
        0 Data access, D:
        1 Program access, P:
        12 AD:
        13 AP:
        15 USR:
        16 VM:

        Additional memory access class values for ARM CPUs
        2 CP0
        3 ICEbreaker
        4 ETM
        5 CP14
        6 CP15
        7 ARM logical
        8 THUMB logical
        9 ARM physical
        10 THUMB physical
        11 ETB
        14 DAP: 
        
        Important : Use 0x40 for E option of memory access (Use it with DAP Enabled)
        '''
    def ReadMemory(self, byteAddress, accessSpecifier, byteSize):
        # TODO: Add a check to make sure bytesize is a factor of 4
        # Return Type: String(INT), Separated by :
        buffer = (c_uint * byteSize)()
        result = ''
        hexResult = ''

        returnCode = self.T32API.T32_ReadMemory(byteAddress, accessSpecifier, byref(buffer), byteSize)
        for i in range(0, int(byteSize / 4)):
            result += str(buffer[i])+':'
            hexResult += self.Dec_To_Hex(buffer[i])+':'

        if returnCode != T32_OK:
            print('- Memory read failed.')
        elif returnCode == T32_OK and self.VERBOSE:
            for i in range(0, int(byteSize / 4)):
                print("Value in INT for index", i, ":", buffer[i])
                print("Value in HEX for index", i, ":", self.Dec_To_Hex(buffer[i]))
        return result[:-1],hexResult[:-1]

    def HexReadMemory(self, byteAddress, accessSpecifier, byteSize):
        # TODO: Add a check to make sure bytesize is a factor of 4
        # Return Type: String(INT), Separated by :
        buffer = (c_uint * byteSize)()
        hexResult = ''

        returnCode = self.T32API.T32_ReadMemory(byteAddress, accessSpecifier, byref(buffer), byteSize)
        for i in range(0, int(byteSize / 4)):
            hexResult += self.Dec_To_Hex(buffer[i]) + ':'

        if returnCode != T32_OK:
            print('- Memory read failed.')

        return hexResult[:-1]

    def ReadHexOneByteMemory(self, byteAddress, accessSpecifier, byteSize):
        buffer = (c_uint * byteSize)()
        hexResult = ''
        returnCode = self.T32API.T32_ReadMemory(byteAddress, accessSpecifier, byref(buffer), byteSize)

        if returnCode != T32_OK:
            print('- Memory read failed.')
        
        return self.Dec_To_Hex(buffer[0])

    # Handle ctypes in the main code. Send only a ctype to this function's buffer argument.
    def WriteMemory(self, byteAddress, accessSpecifier, buffer, byteSize):
        returnCode = self.T32API.T32_WriteMemory(byteAddress, accessSpecifier, byref(buffer), byteSize)
        if returnCode != T32_OK:
            print('- Memory write failed.')
        elif returnCode == T32_OK and self.VERBOSE:
            print('- Memory write success.')

    # This function handles ctypes internally and is used for writing long data in memory.
    def MultiWriteMemory(self, byteAddress, accessSpecifier, writeData, byteSize, byteOrder='little'):
        self.T32API.T32_WriteMemory.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
        self.T32API.T32_WriteMemory.restype  = ctypes.c_int
        buffer = writeData.to_bytes(byteSize, byteorder = byteOrder)

        # Write data to memory via TRACE32
        returnCode = self.T32API.T32_WriteMemory(byteAddress, accessSpecifier, buffer, byteSize)
        if returnCode != T32_OK:
            print('- Memory write failed.')
        elif returnCode == T32_OK and self.VERBOSE:
            print('- Memory write success.')


    '''
    Bit 0 execution breakpoint (Program) (0x01)
    Bit 1 HLL stepping breakpoint (Hll)
    Bit 2 spot breakpoint (Spot)
    Bit 3 read access breakpoint (Read)
    Bit 4 write access breakpoint (Write) (0x10)
    Bit 5 universal marker a (Alpha)
    Bit 6 universal marker b (Beta)
    Bit 7 universal marker c (Charly)
    Bit 8 Set to clear breakpoints
    
    Set size to 4 for one instruction (32 bits)
    Default method is ONCHIP
    For sys_call_table, size = 1524 (conn.WriteBreakpoint(0xc000f924, 0x40, 0x10, 1524))
    '''
    def WriteBreakpoint(self, byteAddress, accessSpecifier, breakpointSpec, size):
        returnCode = self.T32API.T32_WriteBreakpoint(byteAddress, accessSpecifier, breakpointSpec, size)
        if returnCode != T32_OK:
            print('- Breakpoint write failed.')
        elif returnCode == T32_OK and self.VERBOSE:
            print('- Breakpoint write success.')

    def DeleteBreakpoint(self, startAddress = 0x0, endAddress = 0x0):
        if startAddress == 0x0 and endAddress == 0x0:
            self.Command("Break.Delete") # Delete all breakpoints
        elif startAddress != 0x0 and endAddress == 0x0:
            self.Command('Break.Delete ' + hex(startAddress))  # Delete specific breakpoint
        else:
            self.Command('Break.Delete ' + hex(startAddress) + '--' + hex(endAddress))  # Delete specific breakpoint

    def DisableBreakpoint(self, startAddress = 0x0, endAddress = 0x0):
        if startAddress == 0x0 and endAddress == 0x0:
            self.Command("Break.DISable") # Disable all breakpoints
        elif startAddress != 0x0 and endAddress == 0x0:
            self.Command('Break.DISable ' + hex(startAddress))  # Disable specific breakpoint. Only removes that specific address from the breakpoint.
        else:
            self.Command('Break.DISable ' + hex(startAddress) + '--' + hex(endAddress))  # Disable specific breakpoint

    def EnableBreakpoint(self, startAddress = 0x0, endAddress = 0x0):
        if startAddress == 0x0 and endAddress == 0x0:
            self.Command("Break.ENable") # Enable all breakpoints
        elif startAddress != 0x0 and endAddress == 0x0:
            self.Command('Break.ENable ' + hex(startAddress))  # Enable specific breakpoint
        else:
            self.Command('Break.ENable ' + hex(startAddress) + '--' + hex(endAddress))  # Enable specific breakpoint

    def Disable_BBB_Watchdogs(self):
        self.Command("Data.Set AD:0x44E35048 %LE %Long 0x0000AAAA")
        self.Command("Data.Set AD:0x44E35048 %LE %Long 0x00005555")

    def Load_Application(self, appPath, fxnName):
        self.Command("Data.LOAD " + appPath)
        self.Command("Go.direct " + fxnName)
        self.Command("WAIT !STATE.RUN()")

    def GetTaskInformation(self, reqBytes):
        command = 'TASK.DTask'
        return self.GetWindowContent(command, reqBytes, 0x44)

    # Non-intrusive out-of-the-device virtual to physical address translation support for BBB ------------------------
    # Requires the page directory base address
    # kernel, specifies the kernel version
    # device = 'BBB', currently only supported and tested on BBB
    # virtAddress and pgdAddress should be hex string, length will be adjusted to 8 in the function
    def TranslateVirtToPhys(self, device, kernel, virtAddress, pgdBaseAddress):
        physicalAddress = None

        if device == 'BBB' and kernel == '4.19.82-ti-rt-r31':
            # Adjusting the length of the addresses
            virtAddress = '0x' + ('0' * (8 - (len(virtAddress) - 2))) + virtAddress[2:]
            pgdBaseAddress = '0x' + ('0' * (8 - (len(pgdBaseAddress) - 2))) + pgdBaseAddress[2:]

            # Divide the virtual address into global directory index, page table index and offset
            globalDirIndex = '0x' + virtAddress[-8:-5]
            pageTableIndex = '0x' + virtAddress[-5:-3]
            frameOffset = '0x' + virtAddress[-3:]

            # Calculate pgd entry address, get the page table base address, fix its length and then remove last two digits
            pgdEntryAddress = hex(int(pgdBaseAddress, 16) + (int(globalDirIndex, 16) * 4))

            ptBaseAddress = self.HexReadMemory(int(pgdEntryAddress, 16), 0x40, 0x04)
            ptBaseAddress = '0x' + ('0' * (8 - (len(ptBaseAddress) - 2))) + ptBaseAddress[2:]
            ptBaseAddress = ptBaseAddress[:-2] + '00'
            ptEntryAddress = hex(int(ptBaseAddress, 16) + (int(pageTableIndex, 16) * 4))

            frameBaseAddress = self.HexReadMemory(int(ptEntryAddress, 16), 0x40, 0x04)
            frameBaseAddress = '0x' + ('0' * (8 - (len(frameBaseAddress) - 2))) + frameBaseAddress[2:]
            frameBaseAddress = frameBaseAddress[:-3] + '000'
            physicalAddress = hex(int(frameBaseAddress, 16) + (int(frameOffset, 16)))
        else:
            print('- Specified configuration not supported.')

        return physicalAddress

    def WriteBinaryFromList(self, dataList, filePath):
        for dataElement in dataList:
            paddedDataElement = '0x' + ('0' * (8 - (len(dataElement) - 2))) + dataElement[2:]
            byteList = [paddedDataElement[-2:], paddedDataElement[-4:-2], paddedDataElement[-6:-4], paddedDataElement[-8:-6]]

            with open(filePath, 'ab') as output:
                output.write(bytearray(int(i, 16) for i in byteList))

    # Using prevPhysicalAddress variable to fix the missing final page
    def NonIntrusiveSaveBinary(self, filePath, virStartAddress, virEndAddress, pgdBaseAddress, ifCode=True):
        addressCounter = int(virStartAddress, 16)
        addressLimit = int(virEndAddress, 16)
        extractedData = ''
        prevPhysicalAddress = 0

        if int(self.HexReadMemory(int(self.TranslateVirtToPhys('BBB', '4.19.82-ti-rt-r31', hex(addressCounter), pgdBaseAddress), 16), 0x40, 0x04), 16) == 0 and ifCode:
            return

        while True:
            physicalAddress = self.TranslateVirtToPhys('BBB', '4.19.82-ti-rt-r31', hex(addressCounter), pgdBaseAddress)
            print('- \n', filePath, 'Internal VADD:', hex(addressCounter))
            print(filePath, 'Internal PADD:', physicalAddress)

            if addressCounter + 4096 <= addressLimit:
                extractedData += self.HexReadMemory(int(physicalAddress, 16), 0x40, 0x1000) + ':'
            elif addressCounter + 4096 > addressLimit:
                virReadSize = int(virEndAddress, 16) - addressCounter
                extractedData += self.HexReadMemory(int(physicalAddress, 16), 0x40, virReadSize)

            prevPhysicalAddress = physicalAddress
            addressCounter += 4096
            if addressCounter > addressLimit:
                break

        extractedDataList = extractedData.split(':')
        self.WriteBinaryFromList(extractedDataList, filePath)
