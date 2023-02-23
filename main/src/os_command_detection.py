import traceback

from numpy import False_
from utils.simulation import SimulationHelper
from utils.patch import OSCommandInjectionPatch
from utils.constants import *

OPERATION_MODE = SOFT_MODE
PATCHER_PREFERENCE = C
TARGET_DEVICE = WAGO
SYSTEM_LIBRARY = True

# Experiment specific
EXPERIMENT_DIR = None

# OS_COMMAND_INJECTION rule
OS_COMMAND_INJECTION_RULE = 'OS_COMMAND_INJECTION_RULE (ALERT): OS_COMMAND_INJECTION [WRITE_ADDRESS > CODESYS_STACK AND WRITE_ADDRESS > CODESYS_ADDRESS_TABLE] "OS_COMMAND_INJECTION VULNERABILITY DETECTED"'

def setup_simulation_environment(_experimentType, _operationMode, _targetDevice, _writeTrackerState = {}, _requestedAdditionalMemorySnapshots = []):
        global EXPERIMENT_DIR
        simulationHelper = SimulationHelper(_experimentType = _experimentType, _operationMode = _operationMode, _targetDevice = _targetDevice, _cleanStateTracker = _writeTrackerState, _systemLibrary = SYSTEM_LIBRARY)

        if not EXPERIMENT_DIR:
            EXPERIMENT_DIR = simulationHelper.setup_project(chosen_vuln = "os_command")
        else:
            simulationHelper.setup_project(chosen_vuln = "os_command", experiment_dir = EXPERIMENT_DIR)

        simulationHelper.get_plc_snapshot_update(_requestedAdditionalMemorySnapshots)
        simulationHelper.initialize_simulation_state()
        simulationHelper.setup_simulation()

        if _experimentType == VULNERABLE_EXPERIMENT or _experimentType == DEBUG_EXPERIMENT:
            simulationHelper.enable_jump_table_address_detection()
            simulationHelper.enable_block_stack_tracking()

            # Specific call to the os_command_injection
            #simulationHelper.enable_os_command_injection_check()

            # Generic call to memory check breakpoint specified with rules
            simulationHelper.enable_custom_memory_rule(OS_COMMAND_INJECTION_RULE)

            simulationHelper.enable_store_load_tracking(_forceEnableGraphCreation = True)

        return simulationHelper

def os_command_injection():
    try:
        global EXPERIMENT_DIR
        print('\n- Capturing safe input hexdump ...\n')
        #_memorySnapshotsInformation = [[0xb6b1b000, 0xb6c48000, 'libc'], [0xb6ea1000, 0xb6efd000, 'libm']]
        _memorySnapshotsInformation = [[0xb6b56000, 0xb6c83000, 'libc1'], [0xb6edc000, 0xb6f38000, 'libm1']]
        simulationHelper = setup_simulation_environment(_experimentType = CLEAN_EXPERIMENT, _operationMode = OPERATION_MODE, _targetDevice = TARGET_DEVICE, _writeTrackerState = {}, _requestedAdditionalMemorySnapshots = _memorySnapshotsInformation)
        simulationHelper.perform_simulation(simulType = NON_INTERACTIVE)
        _cleanWriteTracker = simulationHelper.retrieve_tracked_intra_stack_frame_writes()
        del simulationHelper

        input('\n- Press Enter to continue to capture exploit input hexdump ...\n')
        _cleanWriteTracker = []
        _memorySnapshotsInformation = [[0xb6b56000, 0xb6c83000, 'libc1'], [0xb6edc000, 0xb6f38000, 'libm1']]
        simulationHelper = setup_simulation_environment(_experimentType = VULNERABLE_EXPERIMENT, _operationMode = OPERATION_MODE, _targetDevice = TARGET_DEVICE, _writeTrackerState = _cleanWriteTracker, _requestedAdditionalMemorySnapshots = _memorySnapshotsInformation)
        simulationHelper.perform_simulation(simulType = NON_INTERACTIVE)

        # Handling vulnerability
        input('\n- Press Enter to continue to patching ...\n')
        while simulationHelper.if_vulnerability_remain():
            vulnerabilityObj = simulationHelper.get_top_vulnerability_object()
            print('\n- Patch Information -\n')
            simulationHelper.print_all(vulnerabilityObj.patchBlockState[2])

            # Patching
            osCommandInjectionPatchObj = OSCommandInjectionPatch(_operationMode = OPERATION_MODE, _patcherPreference = PATCHER_PREFERENCE, _targetDevice = TARGET_DEVICE, _basePath = EXPERIMENT_DIR)
            osCommandInjectionPatchObj.initialize(vulnerabilityObj.appStartAddress, vulnerabilityObj.exploitInstructionLocation, vulnerabilityObj.patchBlockState[2], simulationHelper, vulnerabilityObj.exploitMemoryLocation, vulnerabilityObj.exploitMemoryValue, vulnerabilityObj.suggestedUserInput, vulnerabilityObj.completeLocationMemoryContent, vulnerabilityObj.ifMissingTransitionFunction, vulnerabilityObj.writeAddress)
            
            # Hook should be created before the patch
            inlineHook, hookSize, liveHookAddress = osCommandInjectionPatchObj.create_patch_hook(simulationHelper)
            patch, patchSize, liveCodeCaveAddress = osCommandInjectionPatchObj.create_patch()

            # Patch verification
            isPatchSafe = simulationHelper.verify_patch(inlineHook, hookSize, liveHookAddress, patch, patchSize, liveCodeCaveAddress, osCommandInjectionPatchObj.liveJumpTableEmptyAddress, osCommandInjectionPatchObj.liveJumpTableBaseAddress, vulnerabilityObj.vulnerabilityType)

            if isPatchSafe:
                print("\n[*] Patch is safe for deployment...")
            else:
                print("\n\n[X] Patch is not safe for deployment. Exiting...")
                exit(0)

            input('\n- Press Enter to continue to patching live PLC ...\n')
            osCommandInjectionPatchObj.write_patch()
            osCommandInjectionPatchObj.install_patch()
            osCommandInjectionPatchObj.release_connection()
        del simulationHelper

        _debug = False
        if _debug:
            input('\n- Press Enter to continue to debuging ...\n')
            _memorySnapshotsInformation = [[0xb6b56000, 0xb6c83000, 'libc1'], [0xb6edc000, 0xb6f38000, 'libm1']]
            simulationHelper = setup_simulation_environment(_experimentType = DEBUG_EXPERIMENT, _operationMode = OPERATION_MODE, _targetDevice = TARGET_DEVICE, _writeTrackerState = _cleanWriteTracker, _requestedAdditionalMemorySnapshots = _memorySnapshotsInformation)
            simulationHelper.perform_simulation(simulType = NON_INTERACTIVE)
        
    except KeyboardInterrupt:
        simulationHelper.exit_simulation()
    except Exception as e:
        print('\n--------------------')
        print('EXCEPTION: ', e)
        print('--------------------')
        print('TRACKBACK')
        print('--------------------')
        print(traceback.format_exc())
        print('--------------------')
        simulationHelper.exit_simulation()

#if __name__ == '__main__':
#    main()
