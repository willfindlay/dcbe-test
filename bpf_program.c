#include <uapi/asm/unistd_64.h>
#include <linux/sched.h>

struct policy {
    u8 allow_write;
};

BPF_HASH(policy, u32, struct policy);

static struct policy *create_or_loopup_policy(u32 pid) {
    struct policy temp = {};

    struct policy *p = policy.lookup_or_init(&pid, &temp);

    return p;
};

int allow_write(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();

    if (pid != PID)
        return 0;

    struct policy *p = create_or_loopup_policy(pid);
    if (!p)
        return 0;

    // TODO: be careful of int overflow in full version
    p->allow_write++;

    return 0;
}

int deny_write(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid();

    if (pid != PID)
        return 0;

    struct policy *p = create_or_loopup_policy(pid);
    if (!p)
        return 0;

    if (p->allow_write)
        p->allow_write--;

    return 0;
}

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u32 pid = bpf_get_current_pid_tgid();

    if (pid != PID)
        return 0;

    struct policy *p = create_or_loopup_policy(pid);
    if (!p)
        return 0;

    // only worry about write calls for now
    if (args->id != __NR_write)
        return 0;

    if (!p->allow_write) {
        bpf_trace_printk("killed process\n");
        bpf_send_signal(SIGKILL);
    }


    return 0;
}
