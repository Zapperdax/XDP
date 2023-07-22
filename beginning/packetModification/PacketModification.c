#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

SEC("xdp_modify_source_ip")
int xdp_modify_source_ip_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(struct ethhdr);

    // Check if the packet is an IPv4 packet
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end &&
        eth->h_proto == __constant_htons(ETH_P_IP))
    {

        // Modify the source IP address (example: 192.168.0.100)
        ip->saddr = __constant_htonl(0xc0a80064);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
