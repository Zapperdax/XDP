#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <arpa/inet.h>

#define MAX_BLOCKED_IPS 10

SEC("block_ip")
int rate_limit_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *dataEnd = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(struct ethhdr);

    __u32 blockedIPs[MAX_BLOCKED_IPS] = {
        htonl(0xd04199ee),
        htonl(0xd04199fb),
        htonl(0xd04199fd),
        htonl(0xd075ec45),
        htonl(0x40e9a05b)};

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= dataEnd && eth->h_proto == __constant_htons(ETH_P_IP))
    {
        for (int i = 0; i < MAX_BLOCKED_IPS; i++)
        {
            if (ip->saddr == blockedIPs[i])
            {
                return XDP_DROP;
            }
        }
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
