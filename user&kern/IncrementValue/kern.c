#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1024);
} my_map SEC(".maps");

SEC("socket")
int map_example(struct __sk_buff *skb)
{
    __u32 key = 0;
    __u64 value = 42;

    bpf_map_update_elem(&my_map, &key, &value, BPF_ANY);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
