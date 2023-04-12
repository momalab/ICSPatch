## ICSPatch  
This repository contains the source code for ICSPatch, the local patch server, the LKM patcher, and all the Codesys project files for the Wago PFC 100/200 and BeagleBone Black dataset. ICSPatch patches control application binaries for Codesys runtime and require a physical PLC for a complete end-to-end setup. For easing evaluation, the repository loads a memory snapshot of the vulnerable control application and can verify the generated patch by injecting it in the angr simulation instance. Fully reproducing the results requires a PLC supporting Codesys runtime on a Linux OS. The current version of ICSPatch was tested on Wago PFC 100/200 for Linux-5.10.21 and BeagleBone Black for Linux-4.19.82-ti-rt-r31. Cross-compile the local patch server and the lkm patcher for the target architecture and kernel version. However, evaluation of ICSPatch via injecting the patch in the angr simulation instance can be performed on MacOS/Windows/Linux platform as we package ICSPatch in a docker container.

This repository contains the source code of ICSPatch, the local patch server, the LKM patcher, and all the Codesys project files of the dataset for both the BeagleBone Black and Wago PLCs. The file structure of the repository is as follows:
- experiments: All the files required to run the experiments for ICSPatch.
    - cpu_utilization: The bash and Python script to run the CPU utilization experiments on a PLC.
    - hil: All the Hardware-in-the-Loop files including the MSF desalination plant Simulink model and the Codesys project files for the PLC.
    - iec_projects: Contains the Codesys project files for all the vulnerable control applications in the dataset for BeagleBone Black and Wago.
    -motivation_example: Contains the Codesys project file for the motivation example that involves disabling the execution phase of the scan cycle in the runtime from the control application.
- lkm_patcher: The LKM patcher source code deployed on the target PLC.
    - BBB: Contains the BeagleBone Black LKM patcher source code.
    - Wago: Contains the Wago LKM patcher source code.
- local_patch_server: Contains the local patch server C and Python source code for all platforms. This local patch server connects the ICSPatch server with the LKM patcher and runs on the user level.
    - BBB: C implementation of local patch server for BBB.
    - python_client: Platform-independent Python implementation of the local patch server.
    - Wago: C implementation of local patch server for Wago.
- main: The primary ICSPatch server implementation in Python
    - src: Contains the main source code for all the functionality.
    - Dockerfile: For creating the application container for ICSPatch.

## Installation
- Install docker for the test environment by following the instructions on: https://docs.docker.com/engine/install/ubuntu/
- Run the following commands to build and run the docker container
    ```
    cd ICSPatch/main
    sudo docker build --pull --rm -f "Dockerfile" -t icspatch:latest "."
    sudo docker images // List the images
    sudo docker run -it icspatch:latest
    ```

## Vulnerability Localization and Patch Generation
The vulnerability localization and patch generation algorithm for ICSPatch with references to specific files in the code, function names and line numbers.

```
// Hexdumps are extracted at:
// simulation.py: get_plc_snapshot_update() [567 - 669]
// codesys.py: get_memory_snapshot() [116 - 134]
// If LKM patcher enabled, socketconnector.py: get_memory_page() [136 - 156]
// If JTAG enabled, jtag.py: get_memory_page() [129 - 134]
Input: hexdumps


// Initialize simulation, get simulation state and instruction program counter
// simulation.py: initialize_simulation_state() [671 - 724]
1: sim,state, pc ← INIT_SIM(hexdumps)

// simulation.py: setup_simulation() [831 - 832]
2: end ← CALC_END_ADDR(start,state)

// Enable vulnerability detection rules in simulation
// simulation.py: enable_function_start_tracking() [916 - 918]
// simulation.py: enable_safe_write_tracking() [988 - 990]
// simulation.py: enable_safe_read_tracking() [1009 - 1011]
// simulation.py: enable_block_stack_tracking() [1046 - 1049]
// simulation.py: enable_store_load_tracking() [1116 - 1120]
// simulation.py: enable_jump_table_address_detection() [1368 - 1370]
// simulation.py: enable_custom_memory_rule() [1255 - 1262]
3: sim.ENABLE_DETECTION_RULES()

// simulation.py: initialize_per_simulation_states() [439]
4: ddg ← INIT_DDG()

// simulation.py: perform_simulation() [865 - 901]
5: while pc ̸= end do

// Add instruction node for current instruction, containing its operands
// graph.py: add_store_node() [108]
// graph.py: add_load_node() [82]
// graph.py: add_transition_node() [56]
6: ddg.ADD_INSTR_NODE(pc,state.pc.oprnds)

// simulation.py: check_memory_violation() [1300 - 1302]
7: if state.op = ‘mem_write’ then

// If sim writes to memory, add mem node and connect it to the instr node
// graph.py: add_store_node() [107]
8: ddg.ADD_MEM_NODE(state.mem_write_addr)

// graph.py: add_store_node() [109]
9: ddg.ADD_EDGE(pc,state.mem_write_addr, ‘stores’)

// simulation.py: check_memory_violation() [1303 - 1305]
10: else if state.op = ‘mem_read’ then

// If sim reads from memory, add mem node and connect it to instr node
// graph.py: add_load_node() [83]
11: ddg.ADD_MEM_NODE(state.mem_read_addr)

// graph.py: add_load_node() [84]
12: ddg.ADD_EDGE(state.mem_read_addr, pc, ‘loads’)

// simulation.py: enable_store_load_tracking() [1120]
13: else if state.op = ‘reg_write’ then

// If write to reg, connect instr node to previous reg state (transition node)
// graph.py: add_transition_node() [57]
14: ddg.ADD_EDGE(PRV_REG_STATE(state.pc.oprnd2), pc, ‘next’)
15: end if

// Detect vulnerability using memory violation rules
// simulation.py: perform_simulation() [890]
16: if DETECT_VULNERABILITY(state) then

// Locate DDG traversal starting point
// simulation.py: get_exploit_localization_start_node() [1418 - 1437]
17: start_addr ← GET_COMPARISON_INSTRUCTION(state.block)

// Get code block bounds for DDG traversal
// simulation.py: exploit_localization() [1501]
18: block_start,block_end ← GET_NEAREST_APP_BLOCK_ADR()

// Traverse DDG using DFS algorithm to get patch address
// simulation.py: exploit_localization() [1503]
19: sim_p_addr ← DFS(ddg,start_addr,block_start,block_end)

// Check if patch address is valid
// simulation.py: dfs() [1453 - 1454]
20: if CHECK_RANGE(sim_p_addr,block_start,block_end)is false then
21: FAIL()
22: end if

// For Out-of-Bounds Read/Write and Improper Input Validation, patch.py: OOBWritePatch::initialize() [325 - 343]
// For OS Command Injection, patch.py: OSCommandInjectionPatch::initialize() [520 - 545]
23: b_addr ← GET_BASE_ADDR()

// Create patch based on simulation and deployed PLC information
// For all patches, patch.py BasePatch::create_patch_hook() [179 - 220]
// For Out-of-Bounds Read/Write and Improper Input Validation, patch.py: OOBWritePatch::create_patch() [355 - 457]
// For OS Command Injection, patch.py: OSCommandInjectionPatch::create_patch() [568 - 633]
24: patch,hook,liv_p_addr ← BUILD_PATCH(state,sim_p_addr,b_addr)

// Deploy patch by sending it to the local patch server on the PLC
// For all patches, patch.py BasePatch::write_patch() [222 - 257]
// For all patches, patch.py BasePatch::install_patch() [259 - 280]
25: DEPLOY_PATCH(patch,hook,liv_p_addr)

26: EXIT()
27: end if

// simulation.py: perform_simulation() [869]
28: state, pc ← sim.SIM_STEP()
29: end while
```


## ICSPatch for Evaluation

Running the command `sudo docker run -it icspatch:latest` runs the docker container and executes ICSPatch, displaying the following prompt:
```
Select Vulnerability:
-------------------------
0. improper_input
1. oob_write
2. oob_read
3. os_command
4. exit
Choice: 1
```

In this example, we will evaluate oob_write vulnerabilities in our dataset. Upon pressing `Enter`, the following messages will show up:
```
- Capturing safe input hexdump ...

--------------------
[*] Setting up Clean Experiment ...
[*] Created CodesysConnector object ...
[*] Created Register object ...
[*] Created Memory object ...
[*] Created Simulation Stack object ...
[*] Created Custom Rule object ...
[*] System Library explicitly identified by the user ...
[*] Created Patch Verifier object ...
--------------------
[*] Reduce angr logging level to 'ERROR' ...
[*] Created a blank angr project with thumb LE ...
[*] Created a blank simulation state...

Select Experiment:
-------------------------
0. Evaluate
1. Live
Choice: 0
```

For evaluating ICSPatch, please select **0** as shown above. The evaluation mode uses the memory snapshots of vulnerable control application binaries stored at `main/src/bin/internal/`, while the Live mode will attempt connection with the local patch server running on the target PLC.

Next, the menu will ask to select the target infrastructure from the dataset and display the available control applications for evaluation. Here we select the desalination plant, which has a single oob_write example:
```
Select Infrastructure:
-------------------------
0. aircraft_control
1. anaerobic_reactor
2. chemical_plant
3. desalination_plant
4. smart_grid
Choice: 3

Select Test Sample:
-------------------------
0. bin/internal/desalination_plant/oob_write/code_1
Choice: 0
```

At this point, ICSPatch starts loading the memory snapshot of the vulnerable application running with a safe input to detect crashes that only impact the control application stack.
```
[*] Past PLC snapshot detected ...
- Stored Map Address: 0xb615c000 ...
- Stored App Start Address: 0xb617c010 ...
- Stored Data Start Address: 0xb627c000 ...
[*] Loaded important addresses ...
[*] Loaded register values ...
[*] Loaded memory snapshots ...
[*] Loaded additional memory snapshots ...
.
.
.
[*] Beginning simulation ...
<SimulationManager with 1 active> [<SimState @ 0xb617c010>]
* Considered SL (R10) 0xb617ad68 ...
- Active Address:  0xb617c010
<SimulationManager with 1 active> [<SimState @ 0xb617c050>]
- Active Address:  0xb617c050
<SimulationManager with 1 active> [<SimState @ 0xb617c060>]
.
.
.
[*] Retrieved tracked intra-stack frame writes ...


- Press Enter to continue to capture exploit input hexdump ...
```

Press `Enter` to continue loading memory snapshots of vulnerable control applications with an exploit input. This angr simulation will test our vulnerability detection rule, then attempt to localize the vulnerability by traversing the created DDG and providing information about the exploit location and input to the user.
```
--------------------
[*] Setting up Vulnerable Experiment ...
[*] Created CodesysConnector object ...
[*] Created Register object ...
[*] Created Memory object ...
[*] Created Simulation Stack object ...
[*] Created Custom Rule object ...
[*] System Library explicitly identified by the user ...
[*] Created Patch Verifier object ...
--------------------
.
.
.
--------------------
[*] Beginning simulation ...
<SimulationManager with 1 active> [<SimState @ 0xb617c010>]
* Considered SL (R10) 0xb617ad68 ...
- Active Address:  0xb617c010
<SimulationManager with 1 active> [<SimState @ 0xb617c050>]
- Active Address:  0xb617c050
<SimulationManager with 1 active, 1 deferred> [<SimState @ 0xb617c060>]
.
.
.
- Active Address:  0xb6bbf89c
<SimulationManager with 1 active, 1 deferred> [<SimState @ 0xb6bbf89c>]
* (0xb6bbf8a0) Considered codesys stack register: 0xb617ad58 while writing/reading at 0xb617ad58 ...
* (0xb6bbf8a0) Considered codesys stack register: 0xb617ad58 while writing/reading at 0xb617ad5c ...

***************************
RULE: OUT_OF_BOUNDS_WRITE_RULE
MESSAGE: OUT-OF-BOUNDS WRITE VULNERABILITY DETECTED
***************************
----- BLOCK DISASSEMBLY -----
Instruction # in block: 8
0xb6bbf8a0:    stmhs    r3!, {r1, ip}
0xb6bbf8a4:    subshs    r2, r2, #8
0xb6bbf8a8:    stmhs    r3!, {r1, ip}
0xb6bbf8ac:    subshs    r2, r2, #8
0xb6bbf8b0:    stmhs    r3!, {r1, ip}
0xb6bbf8b4:    subshs    r2, r2, #8
0xb6bbf8b8:    stmhs    r3!, {r1, ip}
0xb6bbf8bc:    bhs    #0xb6bbf89c
------ DEBUG INFO ------
* Instruction Address:  0xb6bbf8a0
* Exploit Memory Address:  0xb617ad5c
* Length:  None
* Expression:  0x0
* (0xb6bbf8a8) Considered codesys stack register: 0xb617ad58 while writing/reading at 0xb617ad60 ...
* (0xb6bbf8a8) Considered codesys stack register: 0xb617ad58 while writing/reading at 0xb617ad64 ...
* (0xb6bbf8b0) Considered codesys stack register: 0xb617ad58 while writing/reading at 0xb617ad68 ...
* (0xb6bbf8b0) Considered codesys stack register: 0xb617ad58 while writing/reading at 0xb617ad6c ...
* (0xb6bbf8b8) Considered codesys stack register: 0xb617ad58 while writing/reading at 0xb617ad70 ...
* (0xb6bbf8b8) Considered codesys stack register: 0xb617ad58 while writing/reading at 0xb617ad74 ...
- Active Address:  0xb6bbf89c
[*] Angr execution time of the control application: 5.889697313308716
* Found start node: 0x83f48d0 ...
- Localization start address list: [138365136] ...
----------0----------
[*] Starting exploit localization from address 0x83f48d0 ...
[*] Start address: 0xb6193fb4 End Address: 0xb6194018...
[*] Bounded by 0xb6193fb4 - 0xb6194018 ...
[*] Search successful for start node 0x83f48d0 ...
[*] Detected exploit location: 0xb6193ff0: str r6, [sp, #8]
[*] Detected exploit input: 0xb617aca0: ['0x2', '0x0', '0x200']
[*] Mermory value at exploit location: 0xb617aca0: 0x00000200
----------0----------

[*] Time for localizing vulnerability: 0.012766838073730469
* Selected vulnerability location is 0xb6193ff0 ...
* Exploit memory location is 0xb617aca0 ...

- Press Enter to continue to patching ...
```

Press `Enter` to continue patching, which displays the basic block in the control application that will be patched to modify the execution flow to the patch, fixing the exploit input in memory by performing simple bounds check. ICSPatch also detects the base address of the jump table and finds an empty location for writing the patch address. For **Evaluation**, please select **Y** for the prompt `Saved patch information detected. Use it?`. ICSPatch will then use the saved information from a live PLC to create and test the patch in the angr simulation instance.
```
- Patch Information -

----- BLOCK DISASSEMBLY -----
Instruction # in block: 26
0xb6193fb4:    str    sl, [sp]
0xb6193fb8:    pop    {fp}
0xb6193fbc:    pop    {sl}
0xb6193fc0:    ldr    r6, [sp, #0xc]
0xb6193fc4:    add    sp, sp, #0x10
0xb6193fc8:    andvs    r0, r0, r0
0xb6193fcc:    vldr    d8, [pc, #0x260]
0xb6193fd0:    vstr    d8, [sl, #-0x38]
0xb6193fd4:    sub    sp, sp, #0x10
0xb6193fd8:    ldr    r4, [pc, #0x260]
0xb6193fdc:    add    r6, sl, r4
0xb6193fe0:    str    r6, [sp]
0xb6193fe4:    mov    r6, #0
0xb6193fe8:    str    r6, [sp, #4]
0xb6193fec:    ldrh    r6, [sl, #0x30]
0xb6193ff0:    str    r6, [sp, #8]
0xb6193ff4:    ldr    fp, [pc, #0x250]
0xb6193ff8:    ldr    r6, [fp]
0xb6193ffc:    mov    r0, sp
0xb6194000:    str    sl, [sp, #-4]!
0xb6194004:    ldr    fp, [pc, #0x23c]
0xb6194008:    str    fp, [sp, #-4]!
0xb619400c:    mov    fp, #0
0xb6194010:    andvs    r0, r0, r0
0xb6194014:    mov    lr, pc
0xb6194018:    mov    pc, r6
----- REGISTER VIEW -----
- R0:  0xb617acd8
- R1:  0x0
- R2:  0x180
- R3:  0xb617ad58
- R4:  0xb617ac98
- R5:  0x0
- R6:  0x83f48c8
- R7:  0x0
- R8:  0x0
- R9:  0x0
- R10:  0xb617ad08
- R11:  0x0
- R12:  0x0
- R13:  0xb617ac88
- R14:  0x83f48d8
- IP:  0xb6bbf89c
- Flags:  0x20000000
--------------------
[*] Created OOB Write patching object ...
- Simulation jump table index: 0
- Simulation jump table base address: 0xb62a50c0
- Detected empty jump table space at 0xb62a50e0 ...

[*] Saved patch information detected. Use it? (Y/N): Y
```

ICSPatch then loads the saved information from a live PLC, creates the patch, loads it in the angr simulation, and verifies it.
```
[*] Patch information loaded ...
- Live user specified bound value 0x00000002 ...
- Live jump table base address 0xb62a50c0 ...
- Live exploit memory location 0xb617aca0 ...

[*] Initialized patching object ...
[*] Creating patch hook for OOB write ...
- Detected return address: 0xb619401c
- Detected hook instruction 0xb6193ff8: ldr r6, [fp, #0x0] ...
- Modified hook instruction: ldr r6, [fp, #0x20] ...
[*] Patch hook to be written at 0xb6193ff8 ...
- Hook in hex: 20609be5
- Disassembly:
   0:   e59b6020        ldr     r6, [fp, #32]
[*] Patch hook creation time: 0.1913595199584961
--------------------
[*] OOBW/OOBR patch creation time: 0.05663704872131348
--------------------
[*] Patch to be written at 0xb61ac000 ...
- Patch in hex: 34608fe200e086e520609fe500e096e51c609fe506005ee110e09fc500608ec510e09fe500609ee50ce09fe506f0a0e1a0ac17b602000000c0502ab6
- Disassembly:
   0:   e28f6034        add     r6, pc, #52     ; 0x34
   4:   e586e000        str     lr, [r6]
   8:   e59f6020        ldr     r6, [pc, #32]   ; 0x30
   c:   e596e000        ldr     lr, [r6]
  10:   e59f601c        ldr     r6, [pc, #28]   ; 0x34
  14:   e15e0006        cmp     lr, r6
  18:   c59fe010        ldrgt   lr, [pc, #16]   ; 0x30
  1c:   c58e6000        strgt   r6, [lr]
  20:   e59fe010        ldr     lr, [pc, #16]   ; 0x38
  24:   e59e6000        ldr     r6, [lr]
  28:   e59fe00c        ldr     lr, [pc, #12]   ; 0x3c
  2c:   e1a0f006        mov     pc, r6
--------------------
[*] Initiating patch verification ...
--------------------
[*] Setup simulation manager ...
[*] Choosing DFS exploration technique ...
[*] Created Register object ...
[*] Created Memory object ...
[*] Created Simulation Stack object ...
[*] Created Custom Rule object ...
[*] Written patch, code cave address, and inline hook in simulation state ...
[*] Enabling patch verification write tracking ...
[*] Enabling dangerous instruction detection ...
--------------------
[*] Beginning simulation ...
<SimulationManager with 1 active> [<SimState @ 0xb617c010>]
* Considered SL (R10) 0xb617ad68 ...
- Active Address:  0xb617c010
<SimulationManager with 1 active> [<SimState @ 0xb617c050>]
- Active Address:  0xb617c050
<SimulationManager with 1 active, 1 deferred> [<SimState @ 0xb617c060>]
.
.
.
```

Once the patch verification is complete, and none of the vulnerability rules are triggered, ICSPatch asks the user to press `Enter` to continue patching a live PLC. Since the PLC is not connected in the Evaluation mode, the attempted socket connection with the local patch server will timeout in 10 seconds, and ICSPatch will exit.

```
.
.
.
<SimulationManager with 1 active, 1 deferred> [<SimState @ 0xb617c074>]
- Active Address:  0xb617c074
[*] Time for patch verification in angr: 7.542086601257324

[*] Patch is safe for deployment...

- Press Enter to continue to patching live PLC ...

Socket connection failed: timed out
Cannot connect to local patch server ... Exiting
```

## ICSPatch with a live PLC

First, cross-compile the local patch server and the LKM patcher for the target PLC platform. In the repository, we provide and test for:
- BeagleBone Black (Linux-4.19.82-ti-rt-r31)
- Wago PFC 100/200 (Linux-5.10.21)

The majority of the steps remain the same as in evaluation mode except for:
- Select **1** for the type of experiment which enables fetching fresh memory snapshots from the development PLC by communicating with the local patch server.
    ```
    Select Experiment:
    -------------------------
    0. Evaluate
    1. Live
    Choice: 1
    ```
- Select **N** for using saved patching information, instructing ICSPatch to fetch new information from the deployed PLC.
    ```
    [*] Saved patch information detected. Use it? (Y/N): N
    ```

## Extending ICSPatch

### New Vulnerabilities in Codesys

Supporting new vulnerabilities requires the following changes:
- Vulnerability Detection Rule: New vulnerabilities will require changes to the existing ruleset. The current rulesets are specified in the `oob_write_detection.py`, `oob_read_detection.py`, `os_command_detection.py`, and `improper_input_validation.py` files for out-of-bounds write, out-of-bounds read, os command injection, and improper input validation, respectively. The ruleset is written in a format similar to the Snort. However, some unique keywords that ICSPatch parses might need to be modified and extended in the sile `simulation.py` in function `process_eval_condition()`.
- Data Dependence Graph (DDG): The DDG might also require modification specifically for transition nodes. ICSPatch recognizes ADD, SUB, and MOV instructions for creating transition nodes. However, due to the optimizations in the shared libraries, other instructions might not be captured by the DDG, requiring support for including it. This can be done in `simulation.py` in function `add_transition_node()` line 1151 - 1158. Changes might also be required in the core DDG graph creation file, `graph.py`.
- Patch: In `patch.py`, all the patches inherit basic implementation from BasePatch class. Patching a new vulnerability might require creating a new patch in `patch.py` and inheriting basic functionality from the BasePatch class.

### Other Runtimes

For supporting other runtimes, ICSPatch might require the following changes apart from the ones mentioned above:
- Control Application Rehosting: ICSPatch supports Codesys and utilizes `angr` to rehost and simulate the execution of control applications. The rehosting and control application requires modifications to support runtime from other vendors.
- Patch and Deployment: The patch deployment process and the patch structure will differ, considering the compiled control application binaries changes.


## Contact us
For more information or help with the setup, please contact Prashant Rajput at prashanthrajput@nyu.edu