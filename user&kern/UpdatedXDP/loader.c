#include <unistd.h>
#include <stdlib.h>
#include <linux/if_link.h>
#include <signal.h>
#include <net/if.h>
#include <assert.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

static int ifindex;
struct xdp_program *prog = NULL;

static void int_exit(int sig)
{
    xdp_program__detach(prog, ifindex, XDP_MODE_SKB, 0);
    xdp_program__close(prog);
    exit(0);
}

static void poll_stats(int map_fd, int interval)
{
    int ncpus = libbpf_num_possible_cpus();
    if (ncpus < 0)
    {
        printf("Error get possible cpus\n");
        return;
    }
    long values[ncpus], prev[ncpus], total_pkts;
    int i, key = 0;

    memset(prev, 0, sizeof(prev));

    while (1)
    {
        long sum = 0;

        sleep(interval);
        assert(bpf_map_lookup_elem(map_fd, &key, values) == 0);
        for (i = 0; i < ncpus; i++)
            sum += (values[i] - prev[i]);
        if (sum)
        {
            total_pkts += sum;
            printf("total dropped %10lu, %ld pkt/s\n",
                   total_pkts, sum / interval);
        }
        memcpy(prev, values, sizeof(values));
    }
}

int main(int argc, char *argv[])
{
    int prog_fd, map_fd, ret;

    struct bpf_object *bpf_obj;

    if (argc != 2)
    {
        printf("Usage: %s IFNAME\n", argv[0]);
        return 1;
    }

    ifindex = if_nametoindex(argv[1]);
    if (!ifindex)
    {
        printf("Failed to convert Interface name to index\n");
        return 1;
    }
    printf("%d", ifindex);
}