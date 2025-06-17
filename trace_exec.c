//go:build ignore
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct event {
    __u32 pid;
    char argv[96];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("kprobe/__arm64_sys_execve")
int handle_exec_kprobe(struct pt_regs *ctx) {
    struct event *e;
    const char *const *argv;
    const char *argp;
    char arg[64];

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;

    argv = (const char *const *)PT_REGS_PARM2(ctx);
    if (!argv)
        goto out;

    // Read argv[0] pointer
    if (bpf_probe_read_user(&argp, sizeof(argp), &argv[0]) != 0 || !argp)
        goto out;

    // Read actual string
    if (bpf_probe_read_user_str(e->argv, sizeof(e->argv), argp) <= 1)
        e->argv[0] = '\0';

out:
    bpf_ringbuf_submit(e, 0);
    return 0;
}