// Server side C/C++ program to demonstrate Socket programming
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>
#include <stdbool.h>
#include <linux/netlink.h>
#include "constants.h"

#define PORT 49152

// Get Codesys process Id
bool file_exists(char *filename)
{
    struct stat   buffer;   
    return (stat (filename, &buffer) == 0);
}

char *read_filename(char *filename)
{
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL)
    {
        printf("Error: could not open file %s", filename);
        return "";
    }

    char *buffer = malloc(256);
    fgets(buffer, 256, fp);
    buffer[strcspn(buffer, "\n")] = 0;
    return buffer;
}

int get_codesys_pid()
{
    char *path = "/proc/";
    struct dirent* dent;
    DIR* srcdir = opendir(path);

    if (srcdir == NULL)
    {
        perror("opendir");
        return -1;
    }

    while((dent = readdir(srcdir)) != NULL)
    {
        struct stat st;
        char comm_path[80];
        char *process_name; 

        if(strcmp(dent->d_name, ".") == 0 || strcmp(dent->d_name, "..") == 0)
            continue;

        if(fstatat(dirfd(srcdir), dent->d_name, &st, 0) < 0)
        {
            perror(dent->d_name);
            continue;
        }

        if(S_ISDIR(st.st_mode))
        {
            snprintf(comm_path, sizeof(comm_path), "%s/%s/%s", "/proc", dent->d_name, "comm");
            if(file_exists(comm_path))
            {
                process_name = read_filename(comm_path);
                //CHANGE: Change codesyscontrol. to the appropriate process name to get the PID
                if(strcmp(process_name, "codesyscontrol.") == 0)
                {
                    return atoi(dent->d_name);
                }
            }
        }
    }
    closedir(srcdir);
    return -1;
}

void get_inmemory_addresses(unsigned int tpid, long long *map_start_address, long long *map_end_address)
{
    char path[50];
    sprintf(path, "/%s/%d/%s", "proc", tpid, "maps");
    printf("- Reading file %s ...\n", path);

    FILE *file_pointer;
    int buffer_length = 256;
    char buffer[buffer_length];

    long long prev_start_address = 0;
    long long prev_end_address = 0;

    file_pointer = fopen(path, "r");
    while(fgets(buffer, buffer_length, file_pointer)){
        char *addresses = strtok(buffer, " ");
        char *start_address = strtok(addresses, "-");
        char *end_address = strtok(NULL, "-");

        long long current_start_address = strtoll(start_address, NULL, 16);
        long long current_end_address = strtoll(end_address, NULL, 16);

        //CHANGE: Change the address here to figure out the memory region start address for other devices
        if(current_start_address > 3063939072){
            break;
        }

        prev_start_address = current_start_address;
        prev_end_address = current_end_address;
    }

    fclose(file_pointer);
    *map_start_address = prev_start_address;
    *map_end_address = prev_end_address;

    return 0;
}

char *decimal_to_binary(int number, int size)
{
    int value;
    char *binary_string = malloc(size + 1);

    for (int index = size, counter = 0; index >= 0; index--, ++counter)
    {
        value = number >> index;

        if(value & 1)
            binary_string[counter] = '1';
        else
            binary_string[counter] = '0';
    }
    binary_string[size + 1] = '\0';
    return binary_string;
}

unsigned char *combine_binary_data(char *cmd_bitstr, char *tpid_bitstr, char *target_address_bitstr, char *payload)
{
    unsigned char *packed_data = malloc(sizeof(char) * 4096);

    char payload_len_bitstr[33];
    strncpy(payload_len_bitstr, decimal_to_binary((int) strlen(payload)/8, 31), 33);
    printf("- Binary payload length: %s\n", payload_len_bitstr);

    sprintf(packed_data, "%s%s%s%s%s\0", cmd_bitstr, tpid_bitstr, target_address_bitstr, payload_len_bitstr, payload);
    return packed_data;
}

//unsigned char *pack_data(unsigned int *cmd, unsigned int *tpid, long long *target_address, char *payload)
unsigned char *pack_data(unsigned char *packed_data)
{
    unsigned char *packed_byte_array = malloc(sizeof(unsigned char) * (int) strlen(packed_data)/8);
    for(int index = 0, counter = 0; index < (int) strlen(packed_data)/8; ++index, ++counter)
    {
        char bit_value[9];
        strncpy(bit_value, &packed_data[(index * 8)], 8);
        bit_value[8] = '\0';

        packed_byte_array[counter] = (int) strtol(bit_value, NULL, 2);
    }

    return packed_byte_array;
}

struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
int sock_fd;
struct msghdr msg;

int communicate_with_lkm(unsigned int tpid, char *cmd_bitstr, char *tpid_bitstr, char *target_address_bitstr, char *payload)
{
    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
    if(sock_fd < 0){
        return -1;
    }

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();

    bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0;
    dest_addr.nl_groups = 0;

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(1024));
    memset(nlh, 0, NLMSG_SPACE(1024));
    nlh->nlmsg_len = NLMSG_SPACE(1024);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    unsigned char *packed_data;
    unsigned char *packed_byte_array;
    
    packed_data = combine_binary_data(cmd_bitstr, tpid_bitstr, target_address_bitstr, payload);
    printf("- Binary payload for LKM: %s\n", packed_data);
    packed_byte_array = pack_data(packed_data);

    printf("- Prepared byte array: \n");
    int i = 0;
    while (i < (int) strlen(packed_data)/8)
    {
        printf("%02X ", (int) packed_byte_array[i]);
        i++;
    }
    printf("\n");

    memcpy(NLMSG_DATA(nlh), packed_byte_array, (int) strlen(packed_data)/8);

    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    printf("- Sending payload to the LKM patcher ...\n");
    sendmsg(sock_fd, &msg, 0);

    recvmsg(sock_fd, &msg, 0);
    printf("- LKM patcher reply: %s\n", (char *)NLMSG_DATA(nlh));

    close(sock_fd);

    if(strcmp((char *)NLMSG_DATA(nlh), "SUCCESS") == 0)
        return 1;
    else if(strcmp((char *)NLMSG_DATA(nlh), "FAIL") == 0)
        return 0;

    return -1;
}

int main(int argc, char const *argv[])
{
    int server_fd, new_socket, valread;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    char tpid_hexstr[5];
    char tpid_bitstr[17];
    unsigned int tpid;

    char target_address_bitstr[33];
    long long target_address;

    long long map_start_address;
    long long map_end_address;

    // Check the operation mode of the local patch server
    unsigned int operation_mode;
    if( argc == 2 ){
      printf("[*] Operating in %s mode ...\n", argv[1]);
    }
    else{
        if( argc > 2 ){
            printf("[X] Too many arguments supplied.\n");
        }
        else{
            printf("[X] One argument expected.\n");
        }
        printf("[X] OPTION 1: TEST (For extracting Codesyscontrol hexdumps)\n");
        printf("[X] OPTION 2: DEPLOY (For patching Codesyscontrol)\n");
        exit(EXIT_FAILURE);
    }

    // Setting operating mode
    if(strcmp(argv[1], "TEST") == 0){
        operation_mode = TEST;
    }
    else if(strcmp(argv[1], "DEPLOY") == 0){
        operation_mode = DEPLOY;
    }
    else{
        printf("[X] Unexpected operation mode.\n");
        exit(EXIT_FAILURE);
    }
       
    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
    {
        perror("Socket failed ...");
        exit(EXIT_FAILURE);
    }
       
    // Forcefully attaching socket to the port 8080
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
    {
        perror("Setsockopt ...");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons( PORT );
       
    // Forcefully attaching socket to the port 8080
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address))<0)
    {
        perror("Bind failed ...");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0)
    {
        perror("Listen ...");
        exit(EXIT_FAILURE);
    }
    
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen))<0)
    {
        perror("Accept ...");
        exit(EXIT_FAILURE);
    }

    // Handling messages from ICSPatch
    char buffer[40960] = {0};
    char message[256];
    while(1){
        bzero(buffer, 40960);
        bzero(message, 256);

        char cmd_bitstr[17];
        unsigned int cmd;

        //It receives command as binary string from ICSPatch
        valread = read(new_socket, buffer, sizeof(buffer));
        if(buffer[0] == '\0'){
            continue;
        }
        printf("\n[*] Bit string received: %s\n", buffer);

        strncpy(cmd_bitstr, &buffer[0], 16);
        cmd_bitstr[16] = '\0';
        cmd = (int) strtol(cmd_bitstr, NULL, 2);

        if(cmd == COMM_QUIT){
            printf("\n[*] Received quit command, closing connection ...\n");
            break;
        }
        else if(cmd == LOCATE_ADDRESSES){
            tpid = get_codesys_pid();
            printf("\n- Calculated PID: %d\n", tpid);

            get_inmemory_addresses(tpid, &map_start_address, &map_end_address);
            printf("- Main task start address: %llu \n", map_start_address);
            printf("- Main task end address: %llu \n", map_end_address);

            char map_start_hexaddress[9];
            char map_end_hexaddress[9];

            sprintf(tpid_hexstr, "%.4x\0", tpid);
            sprintf(map_start_hexaddress, "%.8x\0", map_start_address);
            sprintf(map_end_hexaddress, "%.8x\0", map_end_address);

            printf("\n- Hex PID: %s\n", tpid_hexstr);
            printf("- Hex map start address: %s\n", map_start_hexaddress);
            printf("- Hex map end address: %s\n", map_end_hexaddress);

            //It sends a reply as hex string to ICSPatch: PID(Size: 4) + Map Start Address(Size: 8) + Map End Address(Size: 8)
            sprintf(message, "%s%s%s\0", tpid_hexstr, map_start_hexaddress, map_end_hexaddress);
            printf("- Prepared reply: %s\n", message);

            send(new_socket, message, strlen(message), 0);
            printf("- Message sent to ICSPatch ...\n");
        }
        else if(cmd == GET_PROC_MEMORY && operation_mode == TEST)
        {
            strncpy(target_address_bitstr, &buffer[16], 32);
            target_address_bitstr[32] = '\0';
            target_address = strtoll(target_address_bitstr, NULL, 2);

            char size_bitstr[33];
            long long size;

            strncpy(size_bitstr, &buffer[48], 32);
            size_bitstr[32] = '\0';
            size = strtoll(size_bitstr, NULL, 2);

            char dd_command[256];
            sprintf(dd_command, "dd if=/proc/%d/mem of=0x%08llx_code.bin bs=1 skip=$((0x%08llx)) count=$((0x%08llx))\0", tpid, target_address, target_address, size);
            printf("- Executing command: %s\n", dd_command);
            FILE *fd = popen(dd_command,"w");
            pclose(fd);
            printf("- Hexdump written in the file 0x%08llx_code.bin\n", target_address);

            sprintf(message, "%.4x\0", SUCCESS);
            send(new_socket, message, strlen(message), 0);
            printf("- Message sent to ICSPatch (%s) ...\n", message);
        }
        else if((cmd == VERIFY_MEMORY_LOCATION || cmd == INSTALL_JUMP_ADDRESS || cmd == INSTALL_MICRO_PATCH || cmd == INSTALL_HOOK) && (operation_mode == DEPLOY))
        {
            char payload[4096] = {0};
            bzero(payload, sizeof(payload));

            strncpy(target_address_bitstr, &buffer[16], 32);
            target_address_bitstr[32] = '\0';
            target_address = strtoll(target_address_bitstr, NULL, 2);

            strncpy(payload, &buffer[48], strlen(buffer) - 48);
            payload[strlen(buffer) - 48] = '\0';

            strncpy(tpid_bitstr, decimal_to_binary(tpid, 15), 17);

            printf("\n- Binary command: %s\n", cmd_bitstr);
            printf("- Binary PID: %s\n", tpid_bitstr);
            printf("- Binary target address: %s\n", target_address_bitstr);
            printf("- Binary payload: %s\n", payload);

            printf("\n- Command: %d\n", cmd);
            printf("- Target PID: %d (0x%x)\n", tpid, tpid);
            printf("- Target address: %llu (0x%x)\n", target_address, target_address);

            signed int status = communicate_with_lkm(tpid, &cmd_bitstr, &tpid_bitstr, &target_address_bitstr, &payload);
            if(status == 1)
                sprintf(message, "%.4x\0", SUCCESS);
            else if(status == 0 || status == -1)
                sprintf(message, "%.4x\0", FAILURE);

            send(new_socket, message, strlen(message), 0);
            printf("- Message sent to ICSPatch (%s) ...\n", message);
        }
        else
        {
            printf("[X] Incorrect command ...");
            continue;
        }
        bzero(buffer, 40960);
        bzero(message, 256);
    }
    close(new_socket);
    return 0;
}
