#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct inner_map
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, __u32);
} inner_map1 SEC(".maps"), inner_map2 SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 2);
    __type(key, __u32);
    __array(values, struct inner_map);
} outer_map SEC(".maps") = {
    .values = {&inner_map1,
               &inner_map2}};

SEC("inner_maps")
int inner_maps_prog(struct __sk_buff *skb)
{
    __u32 key1 = 0;
    __u32 value1 = 10;

    bpf_map_update_elem(&inner_map1, &key1, &value1, BPF_ANY);

    __u32 key2 = 0;
    __u32 value2 = 20;
    bpf_map_update_elem(&inner_map2, &key2, &value2, BPF_ANY);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";