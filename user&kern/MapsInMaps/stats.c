#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>

#define PATH "/sys/fs/bpf/"
#define KERN_OBJ_FILE "kern.o"

int main()
{
    int inner_map1_fd, inner_map2_fd;
    __u32 key1 = 0, key2 = 0;
    __u32 value1 = 30, value2 = 40;
    int err;

    inner_map1_fd = bpf_obj_get(PATH "inner_map1");
    if (inner_map1_fd < 0)
    {
        perror("bpf_obj_get inner_map1");
        return 1;
    }

    inner_map2_fd = bpf_obj_get(PATH "inner_map2");
    if (inner_map2_fd < 0)
    {
        perror("bpf_obj_get inner_map2");
        return 1;
    }

    struct bpf_map_info info1 = {};
    __u32 info1_len = sizeof(info1);
    err = bpf_obj_get_info_by_fd(inner_map1_fd, &info1, &info1_len);
    if (err)
    {
        perror("bpf_obj_get_info_by_fd inner_map1");
        return 1;
    }

    struct bpf_map_info info2 = {};
    __u32 info2_len = sizeof(info2);
    err = bpf_obj_get_info_by_fd(inner_map2_fd, &info2, &info2_len);
    if (err)
    {
        perror("bpf_obj_get_info_by_fd inner_map2");
        return 1;
    }

    __u32 updateKey, updateValue;
    printf("Enter Key:");
    scanf("%u", &updateKey);
    printf("Enter Value:");
    scanf("%u", &updateValue);

    err = bpf_map_update_elem(inner_map1_fd, &updateKey, &updateValue, BPF_ANY);
    if (!err)
    {
        printf("Value updated successfully");
    }

    __u32 inner_map1_size = info1.max_entries;
    __u32 inner_map2_size = info2.max_entries;
    __u32 value;

    printf("Value of INNER MAP 1\n");
    for (int key = 0; key < inner_map1_size; key++)
    {
        err = bpf_map_lookup_elem(inner_map1_fd, &key, &value);
        if (err)
        {
            perror("bpf_map_lookup_elem inner_map1");
            return 1;
        }
        printf("key=%u, value=%u\n", key, value);
    }

    printf("\nValue of INNER MAP 2\n");
    for (int key = 0; key < inner_map2_size; key++)
    {
        err = bpf_map_lookup_elem(inner_map2_fd, &key, &value);
        if (err)
        {
            perror("bpf_map_lookup_elem inner_map2");
            return 1;
        }
        printf("key=%u, value=%u\n", key, value);
    }
}