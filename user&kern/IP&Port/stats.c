#include <stdio.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "common/common.h"

#define MAP_PATH "/sys/fs/bpf/ip_and_port_map"

int main()
{
    int map_fd;
    int value = 0;
    struct keys key;
    map_fd = bpf_obj_get(MAP_PATH);
    if (map_fd < 0)
    {
        perror("bpf_obj_get");
        return 1;
    }

    if (bpf_map_lookup_elem(map_fd, &key, &value) < 0)
    {
        perror("bpf_map_lookup_elem");
        return 1;
    }

    printf("Count: %d\n", value);
}