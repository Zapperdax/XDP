#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <net/if.h>

#define PATH "/sys/fs/bpf/"
#define IFNAME "wlp3s0"

int main()
{
    struct bpf_object *obj;
    int if_index, prog_fd;
    char filename[] = "kern.o";
    int err;

    err = bpf_prog_load(filename, BPF_PROG_TYPE_XDP, &obj, &prog_fd);
    if (err)
    {
        fprintf(stderr, "ERROR: Could not load bpf program: %s\n", strerror(-err));
        return 1;
    }

    if_index = if_nametoindex(IFNAME);
    if (!if_index)
    {
        perror("if_nametoindex");
        return 1;
    }

    err = bpf_set_link_xdp_fd(if_index, prog_fd, 0);
    if (err)
    {
        fprintf(stderr, "ERROR: Could not link xdp program to interface (%s): %s\n", IFNAME, strerror(-err));
        return 1;
    }

    if (bpf_object__pin_maps(obj, PATH) < 0)
    {
        fprintf(stderr, "ERROR: Could not pin maps to (%s): %s\n", PATH, strerror(errno));
        return 1;
    }

    printf("Successfully linked XDP program to interface (%s)\n", IFNAME);

    printf("Press ENTER to unping and detach program\n");
    getchar();

    err = bpf_set_link_xdp_fd(if_index, -1, 0);
    if (err)
    {
        fprintf(stderr, "ERROR: Unlinking XDP program: %s\n", strerror(-err));
        return 1;
    }

    if (bpf_object__unpin_maps(obj, PATH) < 0)
    {
        fprintf(stderr, "ERROR: Could not unpin maps from (%s): %s\n", PATH, strerror(errno));
        return 1;
    }

    printf("Successfully unlinked XDP program from interface (%s)\n", IFNAME);

    return 0;
}