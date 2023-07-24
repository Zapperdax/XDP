#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <arpa/inet.h>

#define MAX_ALLOWED_IPS 10

SEC("firewall")
int firewallProg(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *dataEnd = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(struct ethhdr);

    __u32 allowedIPs[MAX_ALLOWED_IPS] = {
        htonl(0xC0A80101),
        htonl(0xC0A80102),
        htonl(0xc0a80a09)};

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= dataEnd && eth->h_proto == __constant_htons(ETH_P_IP))
    {
        for (int i = 0; i < sizeof(allowedIPs) / sizeof(allowedIPs[0]); i++)
        {
            if (ip->saddr == allowedIPs[i])
            {
                return XDP_PASS;
            }
        }
        return XDP_DROP;
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
