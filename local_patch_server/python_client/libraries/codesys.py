import sys
import psutil
import traceback

class Codesys:
    def __init__(self):
        self.codesysPID = ''
        self.mappedStartAddress = 0
        self.mappedAppAddress = 0
        self.codeCaveAddress = 0
        self.mainTaskMapEndAddress = 0

    def get_codesys_pid(self):
        try:
            for process_info in psutil.process_iter():
                if 'codesyscontrol' in process_info.name():
                    return process_info.pid
        except Exception as err:
            print('Error: {}'.format(err))

    def get_map_address(self, codesys_pid):
        print('- Detecting Codesys addresses ...')
        maps_filename = "/proc/{}/maps".format(codesys_pid)
        print("- Maps: {}".format(maps_filename))

        try:
            codesys_maps_file = open(maps_filename, 'r')
        except IOError as e:
            print("[ERROR] Can not open file {}:".format(maps_filename))
            print("I/O error({}): {}".format(e.errno, e.strerror))
            sys.exit(1)

        prev_start_address = 0
        prev_end_Address = 0
        for line in codesys_maps_file:
            sline = line.split(' ')
            start_address, end_Address = int('0x'+sline[0].split('-')[0], 16), int('0x'+sline[0].split('-')[1], 16)
            if start_address > 3063939072:
                break

            prev_start_address = start_address
            prev_end_Address = end_Address
        return prev_start_address, prev_end_Address

    def calculate_codesys_addresses(self, map_start_address):
        mapped_start_address = map_start_address + 0x1E000
        mapped_app_address = map_start_address + 0x20000
        code_cave_address = map_start_address + 0x3B000
        return mapped_start_address, mapped_app_address, code_cave_address

    def get_inmemory_addresses(self):
        try:
            self.codesysPID = self.get_codesys_pid()
            main_task_start_address, self.mainTaskMapEndAddress = self.get_map_address(int(self.codesysPID))
            return self.codesysPID, main_task_start_address, self.mainTaskMapEndAddress
        except Exception as exception:
            print(exception)
            traceback.print_exc()
            sys.exit(1)