#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>

#define PATH "/sys/fs/bpf/tenValuesMap"
int main()
{
    int mapFd, err;
    __u32 key, nextKey;
    __u64 value;

    mapFd = bpf_obj_get(PATH);
    if (mapFd < 0)
    {
        perror("bpf_obj_get");
        return 1;
    }

    printf("Reading All Values From Map\n");
    do
    {
        err = bpf_map_get_next_key(mapFd, &key, &nextKey);
        if (err < 0)
        {
            if (errno == ENOENT)
            {
                break;
            }
            else
            {
                perror("bpf_map_get_next_key");
                return 1;
            }
        }

        if (bpf_map_lookup_elem(mapFd, &nextKey, &value) < 0)
        {
            perror("bpf_map_lookup_elem");
            return 1;
        }
        printf("Key: %u: Value: %lld\n", nextKey, value);
        key = nextKey;
    } while (1);

    key = 0;
    nextKey = 0;
    value = 100;
    do
    {
        err = bpf_map_get_next_key(mapFd, &key, &nextKey);
        if (err < 0)
        {
            if (errno == ENOENT)
            {
                break;
            }
            else
            {
                perror("bpf_map_get_next_key");
                return 1;
            }
        }
        if (bpf_map_update_elem(mapFd, &nextKey, &value, BPF_ANY) < 0)
        {
            perror("bpf_map_update_elem");
            return 1;
        }
        printf("Key: %u: Value: %lld\n", nextKey, value);
        key = nextKey;
    } while (1);
    return 0;
}