#include <linux/init.h>
#include <linux/module.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/sched.h>
#include <asm/pgtable.h>
#include <linux/proc_fs.h>
#include <linux/fdtable.h>
#include <linux/mnt_namespace.h>
#include <linux/swap.h>
#include <linux/mount.h>
#include <linux/ptrace.h>
#include <linux/poll.h>
#include <linux/fs_struct.h>
#include <linux/mempolicy.h>
#include <linux/compat.h>
#include <linux/iommu.h>
#include <linux/ktime.h>

// TODO: Remove artificial delay for debug purposes
#include <linux/delay.h>

// Debug
#define DEBUG

// Commands
#define VALIDATION_COMMAND 499

// Netlink User parameter user parameter, used for communication with userspace
#define NETLINK_USER 31

// Module Description
MODULE_DESCRIPTION("User Process Memory Patching Module");

// Function Signatures
void hex_dump(const void *address, int len);
static int read_process_memory(struct task_struct *task, long target_address, long payload_len,
        unsigned char *patch_payload, unsigned int cmd);

// Netlink Socket
struct sock *nl_sk = NULL;

// Netlink Callback Function
static void nl_callback(struct sk_buff *skb) {

    // Netlink Message Headers
    struct nlmsghdr *nlh;

    // Pointer to netlink received data
    unsigned char *msg_data;

    // Command sent by the client to the LKM
    unsigned int cmd;

    // Sender (Client) and Patch Target Process IDs. 16bits.
    unsigned int cpid, tpid;

    // Virtual memory address to patch. 32-bits due to CPU.
    long target_address = 0;

    // Patch length in bytes. 32-bits due to CPU.
    long payload_len = 0;

    // Pointer to patch payload
    unsigned char *patch_payload;

    // Socket Buffer (sk_buff) Queue/Buffer
    struct sk_buff *skb_out;

    // Reply Messages and lengths
    char *reply_success = "SUCCESS";
    int reply_success_size = strlen(reply_success);
    char *reply_failure = "FAIL";
    int reply_failure_size = strlen(reply_failure);
    char *reply;
    int reply_size = 0;

    // Operation Status for read_process_memory()
    int op_status = -1;

    // Error result variable for netlink message sending
    int res;

    // Task structure pointer
    struct task_struct *task;

    // Target Task found boolean flag
    bool found = false;

    // Print Callback Start Message
    printk(KERN_INFO "Entering: %s\n", __FUNCTION__);

    // Cast skb->data to nlmsghdr struct
    nlh = (struct nlmsghdr*)(skb->data);

    // Received data pointer. Assuming that data is a character array for now
    msg_data = nlmsg_data(nlh);

    // Get Command, Target PID, Starting address to validate/patch and payload length from data
    cmd = (msg_data[0] << 8) + msg_data[1];
    tpid = (msg_data[2] << 8) + msg_data[3];
    target_address = (msg_data[4] << 24) + (msg_data[5] << 16) + (msg_data[6] << 8) + msg_data[7];
    payload_len = (msg_data[8] << 24) + (msg_data[9] << 16) + (msg_data[10] << 8) + msg_data[11];

    // Pointer to patch payload
    patch_payload = &(msg_data[12]);

    // Print received data
//    printk(KERN_INFO "Netlink received msg payload:%s\n", msg_data);
    printk(KERN_INFO "Target PID: %u\nTarget Address: 0x%x (%lu)\nPatch Length:(%lu)\n",
           tpid, target_address, target_address, payload_len);

    // Print payload
    int p = 0;
    for(p=0; p < payload_len; p++){
        printk("%02X ", (int) patch_payload[p]);
    }
    printk("\n");

    // Client Process ID
    cpid = nlh->nlmsg_pid;

    // ===== Memory manipulation section ======
    printk(KERN_ALERT "LKM -- Manipulate Memory -- Starting\n");

    // Get the Read, Copy, Update lock
    rcu_read_lock();

    // Iterate over tasks to find the one with the target PID to patch
    for_each_process(task) {
        // Print current task
        // printk(KERN_DEBUG "Scanning tasks -- pid: %d for process %s\n", task->pid, task->comm);
        // Check if current task pid matches with target pid
        if (task->pid == tpid) {
            printk(KERN_ALERT "Found -- pid %d for process %s\n", task->pid, task->comm);
            // Call read_process_memory() to patch
            op_status = read_process_memory(task, target_address, payload_len, patch_payload, cmd);
            found = true;
            break;
        }
    }

    // Release RCU Lock
    rcu_read_unlock();

    // Print error if process not found
    if (!found) {
        printk(KERN_ALERT "LKM -- Manipulate Memory -- Process not found, aborting\n");
        //return -1;
    }

    // =======================================

    // Set reply depending on success or not
    if (op_status >= 0){
        reply = reply_success;
        reply_size = reply_success_size;
    }else{
        reply = reply_failure;
        reply_size = reply_failure_size;
    }

    // Allocate new netlink message
    skb_out = nlmsg_new(reply_size,0);
    if(!skb_out)
    {
        printk(KERN_ERR "Failed to allocate new skb\n");
        return;
    }

    // Add netlink message to output skb buffer, and get pointer to its NL Header
    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, reply_size, 0);

    // Set dst_group
    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */

    // Write reply message to NL message in output buffer
    strncpy(nlmsg_data(nlh), reply, reply_size);

    // Unicast the netlink message
    res = nlmsg_unicast(nl_sk, skb_out, cpid);
    if(res<0)
        printk(KERN_INFO "Error while sending back to user\n");
}

static int read_process_memory(struct task_struct *task, long target_address,
        long payload_len, unsigned char *patch_payload, unsigned int cmd) {

    // Time
    ktime_t start_time, stop_time, elapsed_time;

    // Operation Success / Failure variable returned by function
    int op_status = 0;

    printk(KERN_INFO "read_process_memory: Reading memory!\n");

    // Find first Virtual Memory Area (VMA) whose end address is greater than target_address.
    struct vm_area_struct *vma = find_vma(task->mm, target_address);
    printk(KERN_INFO "find_vma returned address: %lu\n", vma);

    // Allocate memory for a page structure and a locked indicator for it.
    struct page *pages = kmalloc(PAGE_SIZE, GFP_KERNEL);
    int locked = 1;
    printk(KERN_INFO "kmalloc allocated memory for a page structure with address: %lu\n", pages);

    // While there is a virtual memory area to process.
    while (vma) {

        // Calculate VMA size and number of pages
        int vma_section_size = (int) (vma->vm_end - vma->vm_start);
        unsigned long nr_pages = vma_section_size / PAGE_SIZE;
        printk(KERN_INFO "VMA size: %d\t Number of pages: %lu\t Vma start address: %lu\n", vma_section_size, nr_pages, vma->vm_start);

        // Get VMA permission flags
#ifdef DEBUG
        unsigned long vma_flags = vma->vm_flags;
        printk(KERN_INFO "VMA flags (convert to binary representation): %lu\n", vma_flags);
        printk(KERN_INFO "VMA VM_READ: %lu\n", vma_flags & VM_READ);
        printk(KERN_INFO "VMA VM_WRITE: %lu\n", vma_flags & VM_WRITE);
        printk(KERN_INFO "VMA VM_EXEC: %lu\n", vma_flags & VM_EXEC);
        printk(KERN_INFO "VMA VM_SHARED: %lu\n", vma_flags & VM_SHARED);
        printk(KERN_INFO "VMA VM_MAYREAD: %lu\n", vma_flags & VM_MAYREAD);
        printk(KERN_INFO "VMA VM_MAYWRITE: %lu\n", vma_flags & VM_MAYWRITE);
        printk(KERN_INFO "VMA VM_MAYEXEC: %lu\n", vma_flags & VM_MAYEXEC);
        printk(KERN_INFO "VMA VM_MAYSHARE: %lu\n", vma_flags & VM_MAYSHARE);
        printk(KERN_INFO "VMA VM_DENYWRITE: %lu\n", vma_flags & VM_DENYWRITE);
        printk(KERN_INFO "VMA VM_LOCKED: %lu\n", vma_flags & VM_LOCKED);
        printk(KERN_INFO "VMA VM_DONTCOPY: %lu\n", vma_flags & VM_DONTCOPY);
#endif

        // Iterator and VMA starting address variables
        int i;
        unsigned long section_page_start_address = vma->vm_start;

        // Iterate over the pages in the VMA
        for (i = 0; i < nr_pages; ++i) {

            // Print inspected page start address
            printk("Section page start address: %lu", section_page_start_address);

            // Calculate patching offset
            int patch_offset = target_address - section_page_start_address;
            printk("Patch offset for current page: %d", patch_offset);

            // If offset is greater than page size we're on the wrong page. Skip the page
            if (patch_offset >= PAGE_SIZE){
                printk("Offset %d greater than page size %d, moving to next page.", patch_offset, PAGE_SIZE);
                // Increment section_page_start_address to point to next page
                section_page_start_address += PAGE_SIZE;
                continue;
            }

            // Pin user page into memory with r/w capability w/o permission (FOLL_FORCE). Use pages pointer for pinning.
            // Hold lock according to locked variable.
            //long ret = get_user_pages_remote(task, task->mm, section_page_start_address, 1, FOLL_FORCE, &pages, NULL, &locked);
            long ret = get_user_pages_remote(task->mm, section_page_start_address, 1, FOLL_FORCE, &pages, NULL, &locked);
            printk("Page pinning result: %ld\n", ret);

            // If page is successfully pinned
            if (ret > 0 && pages) {

                // Map allocated page buffer from user space into kernel space and get address to it
                void *page_address = kmap(pages);
                printk("Pinned page address: %lu\n", page_address);

                // Print source buffer content
                printk(KERN_INFO "Source Buffer:\n");
                hex_dump(page_address, PAGE_SIZE);

                // Patching or Validation according to command
                int k = 0;
                if (cmd == VALIDATION_COMMAND){
                    // Validation
		            start_time = ktime_get();
                    for(k = 0; k < payload_len; k++){
                        if (((char *)page_address)[patch_offset + k] != patch_payload[k]){
                            printk(KERN_ALERT "MEMORY MATCH: (memory) %c vs %c (payload)\n", ((char *)page_address)[patch_offset + k], patch_payload[k]);
                            op_status = -1;
                            break;
                        }else{
                            printk(KERN_INFO "MEMORY MATCH: (memory) %c vs %c (payload)\n", ((char *)page_address)[patch_offset + k], patch_payload[k]);
                        }
                    }
                    stop_time = ktime_get();
                    elapsed_time = ktime_sub(stop_time, start_time);
                    printk("[*] Memory verification elapsed time : %lld\n ", ktime_to_ns(elapsed_time));
                }else{
                    // Patching
		            start_time = ktime_get();
                    for(k = 0; k < payload_len; k++){
                        ((char *)page_address)[patch_offset + k] = patch_payload[k];
                        // TODO: Remove artificial delay used for debugging
                        //ssleep(2);
                    }
                    stop_time = ktime_get();
                    elapsed_time = ktime_sub(stop_time, start_time);
                    printk("[*] Patching elapsed time : %lld\n ", ktime_to_ns(elapsed_time));
                }

                // Print source buffer content
                printk(KERN_INFO "Source Buffer after operation:\n");
                hex_dump(page_address, PAGE_SIZE);

                // Release list of pages and unmap them from memory
                put_page(pages);
                kunmap(pages);
                return op_status;

            } else {
                printk("Page pinning failed: %ld\n", ret);
                break;
            }
        }

        // Move on to next VMA
        printk(KERN_INFO " ----------- Next Section\n");
        vma = vma->vm_next;
    }

    // Free buf buffer before returning
    kfree(pages);
    return op_status;
}

// Utility function for printing to the kernel log
void hex_dump(const void *address, int len) {
    // Buffer with characters to print out
    int size = 512;
    unsigned char buff[size + 1];
    // Source buffer
    unsigned char *pc = address;

    // Iterate over characters from the source buffer, filter unprintable characters and
    int i;
    for (i = 0; i < len; i++) {
        // If i is greater than the length, print the full buffer as it is and continue operation
        if ((i % size) == 0) {
            if (i != 0)
                printk(KERN_INFO "  %s", buff);
        }
        // Filter out DEL, NUL, TAB and other unprintable characters by replacing them with dots in the print buffer
        if ((pc[i] < 0x20) || (pc[i] > 0x7e)) {
            buff[i % size] = '.';
        } else {
            buff[i % size] = pc[i];
        }
        buff[(i % size) + 1] = '\0';
    }
    printk(KERN_INFO "  %s", buff);
}

// LKM Initialization Function
static int __init init_lkm(void) {
    printk("Patcher LKM: Entering %s\n",__FUNCTION__);
    //This is for 3.6 kernels and above.
    struct netlink_kernel_cfg cfg = {
            .input = nl_callback,
    };

    // Initialize Netlink Socket
    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
    if(!nl_sk)
    {
        printk(KERN_ALERT "Error creating socket.\n");
        return -10;
    }

    return 0;
}

// LKM Exit Function
static void __exit exit_lkm(void) {
    printk(KERN_INFO "Patcher LKM: Exiting Memory Patcher Module\n");
    netlink_kernel_release(nl_sk);
}

module_init(init_lkm);
module_exit(exit_lkm);

MODULE_LICENSE("GPL");