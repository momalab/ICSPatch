###################
## Message types ##
###################
 
NLMSG_NOOP  = 1
NLMSG_ERROR = 2
NLMSG_DONE  = 3
NLMSG_OVERRUN   = 4
NLMSG_MIN_TYPE  = 0x10

# connection
NETLINK_GENERIC = 16
NETLINK_USER = 31

# flags
NLM_F_REQUEST   = 1

# Commands
VERIFY_MEMORY_LOCATION = 499
LOCATE_ADDRESSES = 500
INSTALL_JUMP_ADDRESS = 501
INSTALL_MICRO_PATCH = 502
INSTALL_HOOK = 503
COMM_QUIT = 504

SUCCESS = 510
FAILURE = 511