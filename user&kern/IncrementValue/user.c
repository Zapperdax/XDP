#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>

int main()
{
    struct bpf_object *obj;
    obj = bpf_object__open_file("kern.o", NULL);
    if (!obj)
    {
        fprintf(stderr, "ERROR: Failed to open BPF object file.\n");
        return 1;
    }

    if (bpf_object__load(obj))
    {
        fprintf(stderr, "ERROR: Failed to load BPF program into kernel.\n");
        bpf_object__close(obj);
        return 1;
    }

    bpf_object__close(obj);
    return 0;
}