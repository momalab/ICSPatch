import traceback
from utils.simulation import SimulationHelper
from utils.patch import OOBWritePatch
from utils.constants import *

OPERATION_MODE = SOFT_MODE
PATCHER_PREFERENCE = C
TARGET_DEVICE = WAGO

# Experiment specific
EXPERIMENT_DIR = None

# Used to handle missing transition functions
SYSTEM_LIBRARY = True

# OOB_WRITE rule
OOB_WRITE_RULE = 'OUT_OF_BOUNDS_WRITE_RULE (ALERT): OOB_WRITE [WRITE_ADDRESS > CODESYS_STACK AND WRITE_ADDRESS < CODESYS_TEXT] "OUT-OF-BOUNDS WRITE VULNERABILITY DETECTED"'

def setup_simulation_environment(_experimentType, _operationMode, _targetDevice, _writeTrackerState = {}, _requestedAdditionalMemorySnapshots = []):
        global EXPERIMENT_DIR
        simulationHelper = SimulationHelper(_experimentType = _experimentType, _operationMode = _operationMode, _targetDevice = _targetDevice, _cleanStateTracker = _writeTrackerState, _systemLibrary = SYSTEM_LIBRARY)

        if not EXPERIMENT_DIR:
            EXPERIMENT_DIR = simulationHelper.setup_project(chosen_vuln = "oob_write")
        else:
            simulationHelper.setup_project(chosen_vuln = "oob_write", experiment_dir = EXPERIMENT_DIR)
            
        simulationHelper.get_plc_snapshot_update(_requestedAdditionalMemorySnapshots)
        simulationHelper.initialize_simulation_state()
        simulationHelper.setup_simulation()

        simulationHelper.enable_function_start_tracking()
        simulationHelper.enable_safe_write_tracking()

        if _experimentType == VULNERABLE_EXPERIMENT or _experimentType == DEBUG_EXPERIMENT:
            simulationHelper.enable_block_stack_tracking()

            # Specific call to the oob_write and improper_input_validation function check
            #simulationHelper.enable_memory_bound_check()

            # Generic call to memory check breakpoint specified with rules
            simulationHelper.enable_custom_memory_rule(OOB_WRITE_RULE)

            simulationHelper.enable_store_load_tracking()

        return simulationHelper

def oob_write():
    try:
        global EXPERIMENT_DIR
        print('\n- Capturing safe input hexdump ...\n')
        _memorySnapshotsInformation = [[0xb6b3e000, 0xb6c6b000, 'libc1'], [0xb6ec4000, 0xb6f20000, 'libm1']]
        simulationHelper = setup_simulation_environment(_experimentType = CLEAN_EXPERIMENT, _operationMode = OPERATION_MODE, _targetDevice = TARGET_DEVICE, _writeTrackerState = {}, _requestedAdditionalMemorySnapshots = _memorySnapshotsInformation)
        simulationHelper.perform_simulation(simulType = NON_INTERACTIVE, isPatchVerification = False)
        _cleanWriteTracker = simulationHelper.retrieve_tracked_intra_stack_frame_writes()
        del simulationHelper

        input('\n- Press Enter to continue to capture exploit input hexdump ...\n')
        _cleanWriteTracker = []
        _memorySnapshotsInformation = [[0xb6b3e000, 0xb6c6b000, 'libc1'], [0xb6ec4000, 0xb6f20000, 'libm1']]
        simulationHelper = setup_simulation_environment(_experimentType = VULNERABLE_EXPERIMENT, _operationMode = OPERATION_MODE, _targetDevice = TARGET_DEVICE, _writeTrackerState = _cleanWriteTracker, _requestedAdditionalMemorySnapshots = _memorySnapshotsInformation)
        simulationHelper.perform_simulation(simulType = NON_INTERACTIVE, isPatchVerification = False)

        # Handling vulnerability
        input('\n- Press Enter to continue to patching ...\n')
        while simulationHelper.if_vulnerability_remain():
            vulnerabilityObj = simulationHelper.get_top_vulnerability_object()
            print('\n- Patch Information -\n')
            simulationHelper.print_all(vulnerabilityObj.patchBlockState[2])

            # Patching
            oobWritePatchObj = OOBWritePatch(_operationMode = OPERATION_MODE, _patcherPreference = PATCHER_PREFERENCE, _targetDevice = TARGET_DEVICE, _basePath = EXPERIMENT_DIR)
            oobWritePatchObj.initialize(vulnerabilityObj.appStartAddress, vulnerabilityObj.exploitInstructionLocation, vulnerabilityObj.patchBlockState[2], simulationHelper, vulnerabilityObj.exploitMemoryLocation, vulnerabilityObj.exploitMemoryValue, vulnerabilityObj.suggestedUserInput, vulnerabilityObj.completeLocationMemoryContent, vulnerabilityObj.ifMissingTransitionFunction)
            
            # Hook should be created before the patch
            inlineHook, hookSize, liveHookAddress = oobWritePatchObj.create_patch_hook(simulationHelper)
            patch, patchSize, liveCodeCaveAddress = oobWritePatchObj.create_patch()

            # Patch verification
            isPatchSafe = simulationHelper.verify_patch(inlineHook, hookSize, liveHookAddress, patch, patchSize, liveCodeCaveAddress, oobWritePatchObj.liveJumpTableEmptyAddress, oobWritePatchObj.liveJumpTableBaseAddress, vulnerabilityObj.vulnerabilityType)

            if isPatchSafe:
                print("\n[*] Patch is safe for deployment...")
            else:
                print("\n\n[X] Patch is not safe for deployment. Exiting...")
                exit(0)

            input('\n- Press Enter to continue to patching live PLC ...\n')
            oobWritePatchObj.write_patch()
            oobWritePatchObj.install_patch()
            oobWritePatchObj.release_connection()
        del simulationHelper

        _debug = False
        if _debug:
            input('\n- Press Enter to continue to debuging ...\n')
            _cleanWriteTracker = []
            _memorySnapshotsInformation = [[0xb6b3e000, 0xb6c6b000, 'libc1'], [0xb6ec4000, 0xb6f20000, 'libm1']]
            simulationHelper = setup_simulation_environment(_experimentType = DEBUG_EXPERIMENT, _operationMode = OPERATION_MODE, _targetDevice = TARGET_DEVICE, _writeTrackerState = _cleanWriteTracker, _requestedAdditionalMemorySnapshots = _memorySnapshotsInformation)
            simulationHelper.perform_simulation(simulType = NON_INTERACTIVE, isPatchVerification = False)
        
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
