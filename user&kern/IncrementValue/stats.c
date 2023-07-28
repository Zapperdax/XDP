#include <stdio.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define MAP_PATH "/sys/fs/bpf/my_map"

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

    if (bpf_map_lookup_elem(map_fd, &key, &value) < 0)
    {
        perror("bpf_map_lookup_elem");
        return 1;
    }

    printf("Value in the map: %d\n", value);
}