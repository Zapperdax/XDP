#ifndef __COMMON_H
#define __COMMON_H

struct keys
{
    __u32 srcIP;
    __u32 destIP;
    __u16 srcPort;
    __u16 destPort;
};

__u32 count = 0;
#endif