//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
}events SEC(".maps");

struct sock_state_event {
    __u32 pid;
    __u32 oldstate;
    __u32 newstate;
};


SEC("tracepoint/sock/inet_sock_set_state")
int trace_tcp_state(struct
trace_event_raw_inet_sock_set_state *ctx){
    struct sock_state_event *event;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if(!event)
        return 0;

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->oldstate = ctx->oldstate;
    event->newstate = ctx->newstate;

    bpf_ringbuf_submit(event, 0);
    return 0;
    event->oldstate = ctx->oldstate;
    event->newstate = ctx->newstate;

    bpf_ringbuf_submit(event, 0);
    return 0;
}
