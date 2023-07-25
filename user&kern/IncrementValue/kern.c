#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct bpf_map_def SEC("maps") my_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1,
};

SEC("increment_map")
int increment_map_prog(struct __sk_buff *skb)
{
    __u32 key = 0;
    __u64 *value;

    value = bpf_map_lookup_elem(&my_map, &key);
    if (value)
    {
        *value += 1;
    }
    else
    {
        __u64 newValue = 1;
        bpf_map_update_elem(&my_map, &key, &newValue, BPF_ANY);
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
