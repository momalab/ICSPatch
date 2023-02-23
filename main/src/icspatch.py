from oob_write_detection import oob_write
from improper_input_validation import improper_input_validation
from oob_read_detection import oob_read
from os_command_detection import os_command_injection

def main():
    vulnerability = ["improper_input", "oob_write", "oob_read", "os_command", "exit"]
    print("Select Vulnerability:\n-------------------------")
    for counter, vuln in enumerate(vulnerability):
        print("{}. {}".format(counter, vuln))
    chosen_vuln = int(input("Choice: "))

    if chosen_vuln == 0:
        improper_input_validation()
    elif chosen_vuln == 1:
        oob_write()
    elif chosen_vuln == 2:
        oob_read()
    elif chosen_vuln == 3:
        os_command_injection()
    elif chosen_vuln == 4:
        exit()
    else:
        print("Incorrect selection ... Exiting")
        exit()

if __name__ == '__main__':
    main()