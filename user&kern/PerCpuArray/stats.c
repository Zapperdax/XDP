#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>

#define PATH "/sys/fs/bpf/cpuPacketsCount"

int main()
{
    int mapFd, ncpus, cpu;
    int err;

    mapFd = bpf_obj_get(PATH);
    if (mapFd < 0)
    {
        perror("bpf_obj_get");
        return 1;
    }

    ncpus = libbpf_num_possible_cpus();
    if (ncpus < 0)
    {
        perror("libbpf_num_possible_cpus");
        return 1;
    }
    printf("CPUS: %d\n", ncpus);
    __u64 values[ncpus];

    for (cpu = 0; cpu < ncpus; cpu++)
    {
        if (bpf_map_lookup_elem(mapFd, &cpu, &values) < 0)
        {
            perror("perf_map_lookup_percpu_elem");
            return 1;
        }
    }

    for (int i = 0; i < sizeof(values) / sizeof(values[0]); i++)
    {
        printf("CPU %d:, Packets: %lld\n", i, values[i]);
    }

    return 0;
}
