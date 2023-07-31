#include <stdio.h>
#include <stdlib.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <errno.h>
#include <net/if.h>

#define IFNAME "enp0s31f6"
#define PATH "/sys/fs/bpf/"

int main()
{
    struct bpf_object *obj;
    int ifIndex, progFd;
    char fileName[] = "kern.o";
    int err;

    err = bpf_prog_load(fileName, BPF_PROG_TYPE_XDP, &obj, &progFd);
    if (err)
    {
        fprintf(stderr, "ERROR Loading BPF Object: %s\n", strerror(-err));
        return 1;
    }

    ifIndex = if_nametoindex(IFNAME);
    if (!ifIndex)
    {
        perror("if_nametoindex");
        return 1;
    }

    err = bpf_set_link_xdp_fd(ifIndex, progFd, 0);
    if (err)
    {
        fprintf(stderr, "ERROR Linking Program To Interface: %s\n", strerror(-err));
        return 1;
    }
    printf("Program Linked To Interface: %s\n", IFNAME);

    if (bpf_object__pin_maps(obj, PATH) < 0)
    {
        fprintf(stderr, "ERROR Pinning Map: %s\n", strerror(errno));
        return 1;
    }
    printf("Program Has Been Pinned To Path: %s\n", PATH);

    printf("\nPress Enter To Unpin Map & Unlink Program From Interface (%s)\n", IFNAME);
    getchar();

    if (bpf_object__unpin_maps(obj, PATH) < 0)
    {
        fprintf(stderr, "ERROR Unpinning Map: %s\n", strerror(errno));
        return 1;
    }

    err = bpf_set_link_xdp_fd(ifIndex, -1, 0);
    if (err)
    {
        fprintf(stderr, "ERROR Unlinking Program: %s\n", strerror(-err));
        return 1;
    }
    printf("Program Unlinked & Unpinned Successfully\n");

    return 0;
}