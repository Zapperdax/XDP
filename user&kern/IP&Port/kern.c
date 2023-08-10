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
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct keys);
    __type(value, __u32);
    __uint(max_entries, 1024);
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
        __u32 srcIP;
        __u32 destIP;
        __u32 value = 0;
        __u16 srcPort = 0;
        __u16 destPort = 0;
        __u8 protocol = ip->protocol;
        srcIP = ip->saddr;
        destIP = ip->daddr;
        if (protocol == IPPROTO_TCP)
        {
            if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) <= data_end)
            {
                struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
                srcPort = ntohs(tcp->source);
                destPort = ntohs(tcp->dest);
            }
            else
            {
                goto out;
            }
        }
        else if (protocol == IPPROTO_UDP)
        {
            if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) <= data_end)
            {
                struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
                srcPort = ntohs(udp->source);
                destPort = ntohs(udp->dest);
            }
            else
            {
                goto out;
            }
        }

        struct keys info = {
            .srcIP = srcIP,
            .destIP = destIP,
            .srcPort = srcPort,
            .destPort = destPort,
        };

        bpf_map_update_elem(&ip_and_port_map, &info, &value, BPF_ANY);
    }

out:
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
