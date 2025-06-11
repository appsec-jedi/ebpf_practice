//go:build ignore
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <linux/ptrace.h>
#include <linux/sched.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct event {
    __u64 timesstamp_ns;
    __u32 pid;
    char comm[16];
    char tty[32];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB ring buffer
} events SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e) {
        return 0;
    }

    // Timestamp in nanoseconds
    e->timesstamp_ns = bpf_ktime_get_ns();
    // PID
    e->pid = bpf_get_current_pid_tgid() >> 32;
    // Command
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}