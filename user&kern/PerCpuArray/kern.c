#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct bpf_map_def SEC("maps") cpuPacketsCount = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 4,
};

SEC("CpuCount")
int packetCounter(struct __sk_buff *skb)
{
    __u32 key = bpf_get_smp_processor_id();
    __u64 *count = bpf_map_lookup_elem(&cpuPacketsCount, &key);
    if (count)
    {
        __sync_fetch_and_add(count, 1);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
