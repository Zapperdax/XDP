#include <stdio.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "common/common.h"

#define MAP_PATH "/sys/fs/bpf/ip_and_port_map"

int main()
{
    int map_fd;
    struct keys key, nextKey;
    __u32 value;
    int ret;

    map_fd = bpf_obj_get(MAP_PATH);
    if (map_fd < 0)
    {
        perror("bpf_obj_get");
        return 1;
    }

    key.srcIP = 0;
    key.destIP = 0;
    key.srcPort = 0;
    key.destPort = 0;

    while (1)
    {
        // Try to lookup the next key-value pair
        ret = bpf_map_get_next_key(map_fd, &key, &key);
        if (ret < 0)
        {
            perror("bpf_map_get_next_key");
            printf("Keys Finished");
            break; // Stop on error
        }

        // Retrieve the value associated with the key from the map
        if (bpf_map_lookup_elem(map_fd, &key, &value) < 0)
        {
            perror("bpf_map_lookup_elem");
            continue; // Continue to the next iteration on error
        }

        printf("Count for key (srcIP=%u, destIP=%u, srcPort=%u, destPort=%u): %d\n",
               key.srcIP, key.destIP, key.srcPort, key.destPort, value);
    }

    return 0;
}
