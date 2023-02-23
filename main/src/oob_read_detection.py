import traceback
from utils.simulation import SimulationHelper
from utils.patch import OOBReadPatch
from utils.constants import *

OPERATION_MODE = SOFT_MODE
PATCHER_PREFERENCE = C
TARGET_DEVICE = WAGO
SYSTEM_LIBRARY = True

# Experiment specific
EXPERIMENT_DIR = None

# OOB_READ rule
OOB_READ_RULE = 'OUT_OF_BOUNDS_READ_RULE (ALERT): OOB_READ [READ_ADDRESS > CODESYS_STACK AND READ_ADDRESS < CODESYS_DATA] "OUT_OF_BOUNDS_READ VULNERABILITY DETECTED"'

def setup_simulation_environment(_experimentType, _operationMode, _targetDevice, _readTrackerState = {}, _requestedAdditionalMemorySnapshots = []):
        global EXPERIMENT_DIR
        simulationHelper = SimulationHelper(_experimentType = _experimentType, _operationMode = _operationMode, _targetDevice = _targetDevice, _cleanStateTracker = _readTrackerState, _systemLibrary = SYSTEM_LIBRARY)

        if not EXPERIMENT_DIR:
            EXPERIMENT_DIR = simulationHelper.setup_project(chosen_vuln = "oob_read")
        else:
            simulationHelper.setup_project(chosen_vuln = "oob_read", experiment_dir = EXPERIMENT_DIR)

        simulationHelper.get_plc_snapshot_update(_requestedAdditionalMemorySnapshots)
        simulationHelper.initialize_simulation_state()
        simulationHelper.setup_simulation()

        simulationHelper.enable_function_start_tracking()
        simulationHelper.enable_safe_read_tracking()

        if _experimentType == VULNERABLE_EXPERIMENT or _experimentType == DEBUG_EXPERIMENT:
            simulationHelper.enable_block_stack_tracking()

            # Specific call to the oob_read
            #simulationHelper.enable_memory_read_check()

            # Generic call to memory check breakpoint specified with rules
            simulationHelper.enable_custom_memory_rule(OOB_READ_RULE)

            simulationHelper.enable_store_load_tracking()

        return simulationHelper

def oob_read():
    try:
        global EXPERIMENT_DIR
        print('\n- Capturing safe input hexdump ...\n')
        _memorySnapshotsInformation = [[0xb6b89000, 0xb6cb6000, 'libc1']]
        simulationHelper = setup_simulation_environment(_experimentType = CLEAN_EXPERIMENT, _operationMode = OPERATION_MODE, _targetDevice = TARGET_DEVICE, _readTrackerState = {}, _requestedAdditionalMemorySnapshots = _memorySnapshotsInformation)
        simulationHelper.perform_simulation(simulType = NON_INTERACTIVE)
        _cleanReadTracker = simulationHelper.retrieve_tracked_intra_stack_frame_reads()
        del simulationHelper

        # VULNERABLE_EXPERIMENT
        input('\n- Press Enter to continue to capture exploit input hexdump ...\n')
        _cleanReadTracker = []
        _memorySnapshotsInformation = [[0xb6b89000, 0xb6cb6000, 'libc1']]
        simulationHelper = setup_simulation_environment(_experimentType = VULNERABLE_EXPERIMENT, _operationMode = OPERATION_MODE, _targetDevice = TARGET_DEVICE, _readTrackerState = _cleanReadTracker, _requestedAdditionalMemorySnapshots = _memorySnapshotsInformation)
        simulationHelper.perform_simulation(simulType = NON_INTERACTIVE)

        # Handling vulnerability
        input('\n- Press Enter to continue to patching ...\n')
        while simulationHelper.if_vulnerability_remain():
            vulnerabilityObj = simulationHelper.get_top_vulnerability_object()
            print('\n- Patch Information -\n')
            simulationHelper.print_all(vulnerabilityObj.patchBlockState[2])

            # Patching
            oobReadPatchObj = OOBReadPatch(_operationMode = OPERATION_MODE, _patcherPreference = PATCHER_PREFERENCE, _targetDevice = TARGET_DEVICE, _basePath = EXPERIMENT_DIR)
            oobReadPatchObj.initialize(vulnerabilityObj.appStartAddress, vulnerabilityObj.exploitInstructionLocation, vulnerabilityObj.patchBlockState[2], simulationHelper, vulnerabilityObj.exploitMemoryLocation, vulnerabilityObj.exploitMemoryValue, vulnerabilityObj.suggestedUserInput, vulnerabilityObj.completeLocationMemoryContent, vulnerabilityObj.ifMissingTransitionFunction)

            # Hook should be created before the patch
            inlineHook, hookSize, liveHookAddress = oobReadPatchObj.create_patch_hook(simulationHelper)
            patch, patchSize, liveCodeCaveAddress = oobReadPatchObj.create_patch()

            # Patch verification
            isPatchSafe = simulationHelper.verify_patch(inlineHook, hookSize, liveHookAddress, patch, patchSize, liveCodeCaveAddress, oobReadPatchObj.liveJumpTableEmptyAddress, oobReadPatchObj.liveJumpTableBaseAddress, vulnerabilityObj.vulnerabilityType)

            if isPatchSafe:
                print("\n[X] Patch is safe for deployment...")
            else:
                print("\n\n[X] Patch is not safe for deployment. Exiting...")
                exit(0)

            input('\n- Press Enter to continue to patching live PLC ...\n')
            oobReadPatchObj.write_patch()
            oobReadPatchObj.install_patch()
            oobReadPatchObj.release_connection()
        _debug = False
        if _debug:
            input('\n- Press Enter to continue to debuging ...\n')
            _memorySnapshotsInformation = [[0xb6b89000, 0xb6cb6000, 'libc1']]
            simulationHelper = setup_simulation_environment(_experimentType = DEBUG_EXPERIMENT, _operationMode = OPERATION_MODE, _targetDevice = TARGET_DEVICE, _readTrackerState = _cleanReadTracker, _requestedAdditionalMemorySnapshots = _memorySnapshotsInformation)
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
