#include <stdio.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "common/common.h"

#define MAP_PATH "/sys/fs/bpf/ip_and_port_map"

int main()
{
    int map_fd, value;
    int key = 0;

    map_fd = bpf_obj_get(MAP_PATH);
    if (map_fd < 0)
    {
        perror("bpf_obj_get");
        return 1;
    }

    while (1)
    {
        printf("MAP VALUES:\n");
        __u32 key = 0;
        struct keys value;

        while (bpf_map_lookup_elem(map_fd, &key, &value) == 0)
        {
            printf("Key: %u, SrcIP: %u, DestIP: %u\n", key, value.srcIP, value.destIP);
            key++;
        }
    }
    return 0;
}