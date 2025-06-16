//go:build ignore
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct event {
    __u64 timestamp_ns;
    __u32 pid;
    char argv[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("kprobe/do_execveat_common")
int handle_exec_kprobe(struct pt_regs *ctx) {
    struct event *e;
    const char *const *argv;
    int offset = 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->timestamp_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;

    argv = (const char *const *)PT_REGS_PARM2(ctx);

#pragma unroll
    for (int i = 0; i < 5; i++) {
        if (offset >= sizeof(e->argv) - 1)
            break;

        // Write directly into the next slot in e->argv
        int bytes = bpf_probe_read_user_str(&e->argv[offset], sizeof(e->argv) - offset, &argv[i]);
        if (bytes <= 1)
            break;  // Empty or null arg

        offset += bytes - 1; // Omit null byte

        if (offset < sizeof(e->argv) - 1) {
            e->argv[offset++] = ' '; // Add space after argument
        }
    }

    // Null-terminate if there's room
    if (offset < sizeof(e->argv))
        e->argv[offset] = '\0';
    else
        e->argv[sizeof(e->argv) - 1] = '\0';

    bpf_ringbuf_submit(e, 0);
    return 0;
}