#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <errno.h>
#include <net/if.h>

#define IFNAME "enp0s31f6"

int main()
{
    struct bpf_object *obj;
    int ifindex, prog_fd;
    char filename[] = "kern.o";
    char prog_name[] = "map_example";
    int err;

    err = bpf_prog_load(filename, BPF_PROG_TYPE_XDP, &obj, &prog_fd);
    if (err)
    {
        fprintf(stderr, "ERROR loading BPF object: %s\n", strerror(-err));
        return 1;
    }

    ifindex = if_nametoindex(IFNAME);
    if (!ifindex)
    {
        perror("if_nametoindex");
        return 1;
    }

    err = bpf_set_link_xdp_fd(ifindex, prog_fd, 0);
    if (err)
    {
        fprintf(stderr, "ERROR attaching XDP program: %s\n", strerror(--err));
        return 1;
    }
    printf("XDP program attached to %s (ifindex: %d)\n", IFNAME, ifindex);

    if (bpf_object__pin_maps(obj, "/sys/fs/bpf/") < 0)
    {
        fprintf(stderr, "ERROR pinning maps: %s\n", strerror(errno));
        return 1;
    }
    printf("XDP program pinned the map\n");
}