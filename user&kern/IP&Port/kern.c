#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "common/common.h"

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct keys);
    __uint(max_entries, 100);
} ip_and_port_map SEC(".maps");

SEC("CatchingIPsAndPorts")
int CatchingIPsAndPortsProg(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(struct ethhdr);

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end &&
        eth->h_proto == __constant_htons(ETH_P_IP))
    {

        __u32 srcIP = ip->saddr;
        __u32 destIP = ip->daddr;
        __u32 key = 0;
        struct keys info = {
            .srcIP = srcIP,
            .destIP = destIP,
        };
        bpf_map_update_elem(&ip_and_port_map, &key, &info, BPF_ANY);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";