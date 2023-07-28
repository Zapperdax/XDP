#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#define RATE_LIMIT 1000
#define NANOSECONDS 1000000000UL

struct bpf_map_def SEC("maps") timestamps = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1024};

SEC("rate_limit")
int rate_limit_prog(struct xdp_md *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(struct ethhdr);

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end &&
        eth->h_proto == __constant_htons(ETH_P_IP))
    {
        __u32 key = ip->saddr;
        __u64 *timestamp = bpf_map_lookup_elem(&timestamps, &key);

        if (!timestamp)
        {
            __u64 curr_time = bpf_ktime_get_ns();
            bpf_map_update_elem(&timestamps, &key, &curr_time, BPF_ANY);
            return XDP_PASS;
        }

        __u64 curr_time = bpf_ktime_get_ns();
        __u64 delta_time = curr_time - *timestamp;

        if (delta_time < NANOSECONDS / RATE_LIMIT)
        {
            return XDP_DROP;
        }

        bpf_map_update_elem(&timestamps, &key, &curr_time, BPF_ANY);
    }
    return XDP_PASS;
}
