import numpy as np
import re

'''
Top CPU state labels:
    us, user    : time running un-niced user processes
    sy, system  : time running kernel processes
    ni, nice    : time running niced user processes
    id, idle    : time spent in the kernel idle handler
    wa, IO-wait : time waiting for I/O completion
    hi : time spent servicing hardware interrupts
    si : time spent servicing software interrupts
    st : time stolen from this vm by the hypervisor
'''

# === Configuration Variables ===
# Time in seconds
TIME = 3600

if __name__ == '__main__':

    # CPU States
    states_mat = np.loadtxt('states_wago.csv', delimiter=',')
    states_means = np.mean(states_mat, axis=0)
    print("=== Mean CPU time (%) spent in: ===")
    print("Un-niced User Processes: {}".format(states_means[0]))
    print("Kernel processes: {}".format(states_means[1]))
    print("Niced user processes: {}".format(states_means[2]))
    print("Kernel idle handler: {}".format(states_means[3]))
    print("I/O completion: {}".format(states_means[4]))
    print("Hardware interrupt servicing: {}".format(states_means[5]))
    print("Software interrupt servicing: {}".format(states_means[6]))
    print("Time stolen from this vm by the hypervisor: {}".format(states_means[7]))

    # Regex atterns for blocks.csv
    block_pattern_text = r'^(?P<pid>\d+),\s(?P<cpu_perc>\d+\.\d+),\s(?P<cpu_time>\d+:\d+.\d+),\s(?P<pname>\w+)'
    block_pattern = re.compile(block_pattern_text)
    time_pattern_text = r'(?P<minutes>\d+):(?P<seconds>\d+).(?P<milliseconds>\d+)\d+'
    time_pattern = re.compile(time_pattern_text)

    # Process table for final appearance of a process in blocks.csv
    process_table={}
    # Process table for initial appearance of a process in blocks.csv
    process_table_init={}

    # Parse blocks.csv
    with open('blocks_wago.csv') as blocks_f:
        blocks_lines = blocks_f.readlines()

        for block_line in blocks_lines:
            block_match = block_pattern.match(block_line)

            # If the process is one of these, skip processing it.
            # These processes span periodically with different PIDs and polute the log
            if block_match.group('pname') in ('top', 'logrotate', 'irq', 'sh'):
                continue

            time_match = time_pattern.match(block_match.group('cpu_time'))
            time = int(time_match.group('minutes')) * 60 + int(time_match.group('seconds')) + 0.1 * int(
                time_match.group('milliseconds'))

            # Record initial appearance of the process to know how long the process was already running when the bash script ran
            if block_match.group('pid') not in process_table_init:
                process_table_init[block_match.group('pid')] = {'cpu_time': time,
                                                           'pname': block_match.group('pname'),
                                                           'pid': block_match.group('pid')}

            # Record latest appearance of the process in the file to know final cumulative cpu time
            process_table[block_match.group('pid')] = {'cpu_time': time,
                                                       'pname': block_match.group('pname'),
                                                       'pid': block_match.group('pid')}

        print("\n\n=== Processes: ===")
        for process in process_table:
            print("{}, PID:{}, Time%: {}".format(process_table[process]['pname'],
                                                 process_table[process]['pid'],
                                                 (process_table[process]['cpu_time'] - process_table_init[process]['cpu_time']) * 100 / TIME))