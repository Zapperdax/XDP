#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp_pass")
int xdp_pass_prog(struct __sk_buff *skb)
{
    return XDP_PASS;
}

char _license[] SEC("license") = "GLP";