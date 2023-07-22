#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>

SEC("xdp_redirect")
int xdp_redirect_prog(struct __sk_buff *skb)
{
    int ifindex = 3;
    bpf_redirect(ifindex, 0);
    return XDP_DROP;
}

char _license[] SEC("license") = "GLP";