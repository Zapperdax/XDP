#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>

#define PATH "/sys/fs/bpf/tenValuesMap"
int main()
{
    int mapFd, err;
    __u32 key;
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
        err = bpf_map_get_next_key(mapFd, &key, &key);
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

        if (bpf_map_lookup_elem(mapFd, &key, &value) < 0)
        {
            perror("bpf_map_lookup_elem");
            return 1;
        }
        printf("Key: %u: Value: %lld\n", key, value);
    } while (1);
    return 0;
}