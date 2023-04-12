## Dataset

The directory `iec_projects` contains control application project files for Codesys corresponding to all the vulnerable and clean examples in the dataset for Wago PFC 100/200 (`Wago`) and BeagleBone Black (`BBB`).

The `hil`, directory contains the Simulink model for the MSF desalination plant and the corresponding control application project file with out-of-bounds write vulnerability for Wago PFC 100.

The `motivation_example` directory contains the control application for Codesys corresponding to the motivation example, as shown in Figure 2 of ICSPatch \[1\].

Finally, the directory `cpu_utilization` contains the scripts for monitoring CPU utilization for an hour on a Wago PFC 100 and 200 PLC.

Note: All the experiments were performed for Codesys Control 4.0.0.0.

## Motivation Example Experiment

To perform this experiment, open the `Stop Runtime.project` file in Codesys IDE and load the program on a Codesys-compatible PLC. Then, set a breakpoint in the `PLC_PRG` of the program and execute the control application.

The breakpoint is triggered in the first execution of the scan cycle before the value at `0xb62beb82` can be overwritten by the vulnerability in the control application. Upon resuming execution, the breakpoint will trigger again. This is because the control application overwrites the value at `0xb62beb82`, which is being verified by the runtime. As a result, the runtime keeps skipping the execution phase of the scan cycle.

## Execution Timings and Overheads Experiment
For performing the execution timings and overheads experiments as shown in Table 3 \[1\], utilize the control application dataset present in the `iec_projects`. Before beginning, ensure that the local patch server (`local_patch_server/Wago/wago_local_patch_server`) and the LKM patcher (`lkm_patcher/Wago/wago_patcher.ko`) are both running on the experimental PLC.

1. Open the project files in Codesys IDE and load the control application on Wago PFC 100. 
2. The control applications contain comments with legitimate inputs to certain variables. Replace the values of the specified variables with the commented value so that the control application can be properly loaded on the PLC.
3. After loading the program, create a boot project for the control application and reboot the PLC. 
4. The legitimate control application without the exploit input runs as a boot project on the PLC. Stop the execution of the control application.
5. Force write the exploit input specified as comments in the program to the appropriate variable.
6. Now that the control application has the exploit input loaded in memory, use ICSPatch to extract memory snapshots from the Codesys runtime, control application, and some shared libraries, as shown in the *Preparation* phase in Figure 7 of ICSPatch \[1\]. Before beginning, select the correct vulnerability from the menu, as explained in the Section [ICSPatch for Evaluation](../main/README.md).
7. Once ICSPatch completes fetching the memory snapshot with the exploit input, remove the exploit input from the variable and replace it with legitimate input. Then, resume the execution of the control application.
7. Once ICSPatch fetches the memory snapshots by communicating with the local patch server, it sets up the `angr` simulation instance and executes the control application by automatically detecting the `PLC_PRG`.
8. Once, it detects the vulnerability, it will ask for a user-defined bound (except for OS command injection). Once entered, ICSPatch generates the patch by getting base addresses from the local patch server.
9. Confirm the prompt to continue with the patch deployment. Note that the control application is currently executing. 
10. Once the control application is patched, halt its execution, force the exploit input, and check for a crash. Since the control application is patched, the exploit input will not lead to a crash. However, a crash can be verified by restarting the PLC and forcing the exploit input without the patch.

Most of the steps mentioned here are similar to the ones mentioned in the Section [ICSPatch for Evaluation](../main/README.md). The instruction mentioned above clarifies the sequence of events to perform the experiments.

## MSF Desalination Plant Hardware-in-the-Loop (HiL) Experiment
The execution steps for ICSPatch are similar to those mentioned above and also elaborated upon in the Section [ICSPatch for Evaluation](../main/README.md).

However, make sure to perform the following steps before collecting the memory snapshot:
1. Setup the experiment as mentioned in Section 8 (Case Study: Hotpatching Out-of-bounds Write Vulnerability) of ICSPatch \[1\], such that the MSF desalination plant Simulink model is connected via DAQ to Wago PFC 100.
2. Load and execute the control application `hil/wago_pfc_100/Desalination.project` on Wago PFC 100.
3. Start executing the HiL model. To verify the correct setup, the input values of the control application should have been modified from the default zero values. Furthermore, the Simulink model should also be working correctly.

To perform the experiment with a single PLC:
1. Stop the MSF desalination plant Simulink model.
2. Stop the control application execution.
3. Load the exploit input in the control application and collect memory snapshots.
4. Remove the exploit input, apply legitimate input, restart the execution of the control application, and restart the Simulink model.
5. Continue following the instructions mentioned above and patch the control application.
6. Once the patching is complete, enable `ifEnabled` variable for either `WD` or `TB0` in `wdSizeFxn` or `tbSizeFxn` function block in the Simulink model, triggering the data injection attack at the 100th simulation cycle, as shown in Figure 12 of ICSPatch \[1\].
![](images/hil_in_enabled.png?raw=true)
7. Since the control application is patched, the physical process should work correctly without crashing.

## CPU Utilization Experiment

The directory `cpu_utilization` contains two scripts for calculating the CPU utilization.
- `codesys_monitor_top_v4_sh.sh` is the bash script implementation, which does not require a Python interpreter on the target PLC. This script was executed for collecting CPU utilization for processes on Wago PFC 100 and 200 for ICSPatch results \[1\].
- `monitor_postprocessor.py` is the Python implementation for collecting CPU utilization statistics.

To perform the ICSPatch overhead experiments shown in Figures 9 and 10 in \[1\], please run the `codesys_monitor_top_v4_sh.sh` bash script on Wago PFC 100 and 200.

## References
\[1\] Rajput, Prashant Hari Narayan, Constantine Doumanidis, and Michail Maniatakos. "ICSPatch: Automated Vulnerability Localization and Non-Intrusive Hotpatching in Industrial Control Systems using Data Dependence Graphs." USENIX Security Symposium. 2023.