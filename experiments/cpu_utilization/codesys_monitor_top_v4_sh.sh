#!/usr/bin/env bash

: '
This script uses top to monitor the elapsed CPU time of a process in real time.
Top reports the task elapsed CPU time since the last screen update, expressed as a percentage of total CPU time.
'

: '
Sources:
    - https://man7.org/linux/man-pages/man1/top.1.html
    - https://stackoverflow.com/questions/1221555/retrieve-cpu-usage-and-memory-usage-of-a-single-process-on-linux

Top Arguments:
    -b: Batch-mode
    -n 2: Number-of-iterations, use 2 because: When you first run it, it has no previous sample to compare to, so these initial values are the percentages since boot.
    -d: Delay-time(in second, here is 200ms)
    -p: PID
    tail -1: the last row
    awk: print 9th (CPU percentage since last screen update) and 11th (cumulative CPU time since process start) columns

Top CPU state labels:
    us, user    : time running un-niced user processes
    sy, system  : time running kernel processes
    ni, nice    : time running niced user processes
    id, idle    : time spent in the kernel idle handler
    wa, IO-wait : time waiting for I/O completion
    hi : time spent servicing hardware interrupts
    si : time spent servicing software interrupts
    st : time stolen from this vm by the hypervisor
'

# === Configuration Parameters ===

# Time interval between screen updates in seconds.tenths format
DELAY=1.0

# Number of seconds to run for. Set to 3600 (=1hour*60min*60sec) to run for 1 hour.
DURATION_S=3600

# Number of top processes to monitor
NPROCS=10

# Results arrays. CPU Percentage and Cumulative CPU time arrays
OUT=()
CPU_STATES=()

# Set Input Field Separator
IFS=$'\n'

# === Main ===
echo -e "Monitoring tasks for $DURATION_S seconds.\n"

END_SEC=$((SECONDS+DURATION_S))
while [ $SECONDS -lt $END_SEC ]; do
    # Get top output in batch mode with 2 screen updates and a delay in between
    TOP_OUT=$(top -b -n 2 -d $DELAY)
    # Filter out the top NPROCS lines and the header line, remove the header line, replace commas with dots, get PID, CPU%, CPU time and process name
    JOINT=$(echo "$TOP_OUT" | grep "COMMAND" -A $NPROCS | tail -$NPROCS | sed -e 's/,/\./g' | awk '{printf "%s, %s, %s, %s\n", $1, $9, $11, $12}')

    OUT+=("${JOINT}")

    # Get the CPU state line, keep the last line from the 2 top screen updates, remove the %Cpu(s):\s preamble, change commas to dots, remove identifiers, remove trailing 'st'
    # CPU_STATES+=($(echo "$TOP_OUT" | grep '%Cpu(s)' | tail -n 1 | sed -e 's/%Cpu(s):\s*//g' | sed -e 's/,/\./g' | sed -e 's/\s*[a-z]\{2\}.\s*/\, /g' | sed -e 's/\s*st\s*//g'))
    CPU_STATES+=($(echo "$TOP_OUT" | grep '%Cpu(s)' | tail -n 1 | sed -e 's/%Cpu(s):\s*//g;s/,/\./g;s/\s*[a-z]\{2\}.\s*/\, /g;s/\s*st\s*//g'))

    echo -e "\e[1A\e[KElapsed time: $((SECONDS)) / $DURATION_S s"
    # echo "CPU Percentage: $CPU_PERC, CPU Time: $CPU_TIME"
done

# === Output Results ===
for block in ${OUT[@]}; do
    echo "$block" >> blocks.csv
done

for state in ${CPU_STATES[@]}; do
    echo "$state" >> states.csv
done

# echo "Results in cpu_percentage.csv and cpu_time.csv"
echo "Results in blocks.csv, states.csv"
