#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 10);
} tenValuesMap SEC(".maps");

SEC("xdp")
int tenValues(struct __sk_buff *skb)
{
    __u32 key;
    __u64 value;

    key = 0;
    value = 0;
    bpf_map_update_elem(&tenValuesMap, &key, &value, BPF_ANY);

    key = 1;
    value = 1;
    bpf_map_update_elem(&tenValuesMap, &key, &value, BPF_ANY);

    key = 2;
    value = 4;
    bpf_map_update_elem(&tenValuesMap, &key, &value, BPF_ANY);

    key = 3;
    value = 9;
    bpf_map_update_elem(&tenValuesMap, &key, &value, BPF_ANY);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
