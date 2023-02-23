"""
This module contains code pertaining to the generic messaging on a Netlink socket.
"""
 
#There are three levels to a Netlink message: The general Netlink
#message header, the IP service specific template, and the IP service
#specific data.
     
# 0                   1                   2                   3
# 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#|                                                               |
#|                   Netlink message header                      |
#|                                                               |
#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#|                                                               |
#|                  IP Service Template                          |
#|                                                               |
#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#|                                                               |
#|                  IP Service specific data in TLVs             |
#|                                                               |
#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 
import struct
from struct import Struct
from .constants import *
import os

def align(l, alignto=4):
    """Aligned length to nearest multiple of 4."""
    return (l + alignto - 1) & ~(alignto - 1)
 
class Message:
    """Object representing the entire Netlink message."""
    #0                   1                   2                   3
    #0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                          Length                             |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|            Type              |           Flags              |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                      Sequence Number                        |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    #|                      Process ID (PID)                       |
    #+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     
    #struct nlmsghdr {
    #   __u32 nlmsg_len;    /* Length of message including header. */
    #   __u16 nlmsg_type;   /* Type of message content. */
    #   __u16 nlmsg_flags;  /* Additional flags. */
    #   __u32 nlmsg_seq;    /* Sequence number. */
    #   __u32 nlmsg_pid;    /* PID of the sending process. */
    #};
     
    nlmsghdr = Struct("IHHII")
     
    @classmethod
    def unpack(cls, content):
        """Unpack raw bytes into a Netlink message."""
        mlength, type, flags, seq, pid = cls.nlmsghdr.unpack(content[:cls.nlmsghdr.size])
        msg = Message(type, flags, seq, content[cls.nlmsghdr.size:])
        msg.pid = pid
        return msg
     
    def __init__(self, type, flags=0, seq=-1, payload=None, pid=None, address=None, payload_len=0, command=INSTALL_MICRO_PATCH):
        """Used for creating Netlink messages."""
        self.type = type
        self.flags = flags
        self.seq = seq
        self.pid = 0
        self.payload = []

        if pid:
            # Customized for ICSPatch
            # Command towards the LKM: 499 does memory validation, 500+ do patching
            cmd = format(command, "016b")
            # Target PID encoded in a bit string - Maximum PID is 16bits
            tpid = format(pid, "016b")
            # Target Virtual Address encoded in a bit string - 32 bits because of 32 bit CPU
            address = format(address, "032b")
            # Patch payload size in bytes.
            # The payload length number is 32 bits because a long C integer is 4 bytes on the target CPU
            payload_len = format(payload_len, "032b")
            # Join the bit strings
            joint = cmd + tpid + address + payload_len + payload
            # Split them to byte strings
            split = [joint[i:i+8] for i in range(0, len(joint), 8)]
            # Convert bit strings to byte sized ints
            split_bytes = [int(x, 2) for x in split]
            # Convert to bytes
            self.payload = bytes(split_bytes)
        elif isinstance(payload, list):
            self.payload = bytes(payload)
        elif isinstance(payload, str):
            self.payload = payload.encode()
        else:
            self.payload = payload

 
    def __len__(self):
        """Aligned length of service template message + attributes."""
        return align(self.nlmsghdr.size + len(self.payload))
     
    def pack_header(self):
        return self.nlmsghdr.pack(len(self), self.type, self.flags, self.seq, self.pid)
 
    def pack(self):
        return self.pack_header() + self.payload
     
    def __repr__(self):
        return '<netlink message type=%s, pid=%s, seq=%s, flags=0x%x "%s">' % (
            self.type, self.pid, self.seq, self.flags, repr(self.payload))