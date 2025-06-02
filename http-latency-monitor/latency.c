//go:build ignore

#include "common.h"
#include "bpf_tracing.h"
#include "bpf_endian.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct latency_event {
    __u64 pid_tgid;
    __u64 latency_ns;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, __u64);
} start_times SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

// Entry point - record start time
SEC("uprobe/handleRequest")
int uprobe_handle_request(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 start_time = bpf_ktime_get_ns();
    
    bpf_map_update_elem(&start_times, &pid_tgid, &start_time, BPF_ANY);
    return 0;
}

// Exit point - calculate latency
SEC("uretprobe/handleRequest")
int uretprobe_handle_request(struct pt_regs *ctx) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 *start_time;
    
    start_time = bpf_map_lookup_elem(&start_times, &pid_tgid);
    if (!start_time) {
        return 0;
    }
    
    __u64 end_time = bpf_ktime_get_ns();
    __u64 latency = end_time - *start_time;
    
    struct latency_event event = {};
    event.pid_tgid = pid_tgid;
    event.latency_ns = latency;
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    bpf_map_delete_elem(&start_times, &pid_tgid);
    
    return 0;
} 